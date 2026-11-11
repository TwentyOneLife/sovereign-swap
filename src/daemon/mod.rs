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

use std::fs::{File, OpenOptions, TryLockError};
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

use crate::electrum::ElectrumBackend;
use crate::engine::Engine;
use crate::envelope::Identity;
use crate::feescan;
use crate::node::{ChainBackend, ChainNode};
use crate::routing::RelayTransport;
use crate::rpc::Client;
use crate::signer::{InteractiveSigner, RemoteSigner};
use crate::ws::WsConn;

/// How often the engine thread drives a swap forward when no command arrives.
mod engine;
mod reference;
mod types;
// Visible to the reference signer's service module (`crate::signer_server`), which reuses the HTTP
// request reader and the constant-time auth comparison rather than reinventing a web server (design
// 0012). This is a visibility change only; the daemon's funding path is untouched.
pub(crate) mod wire;

pub use engine::SwapView;
pub use types::{parse_btc_to_sats, Chain, FundingConfig, FundingMode, Settings, Signer};

/// Per-call budget for a remote funding signer (design 0012): shorter than a node's long onion
/// budget, since funding signing is one round trip at the start of a swap, when there is time, and a
/// stalled signer must never hang the engine thread.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(60);

use engine::{engine_config, offer_to_json, run_engine, EngineCmd};
use reference::Reference;
use types::NewOffer;
use wire::{
    constant_time_eq, load_or_make_seed, load_or_make_token, offer_id_of, path_id, reachable,
    read_request, reason, valid_id, Request,
};

/// The GUI (design 0009), embedded in the binary and served on the loopback API. `index.html` carries
/// a `__TOKEN__` placeholder the daemon fills with the API token before serving it.
const INDEX_HTML: &str = include_str!("../gui/index.html");
const APP_CSS: &str = include_str!("../gui/app.css");
const APP_JS: &str = include_str!("../gui/app.js");

/// Fuzz entry: run the HTTP request reader over arbitrary bytes (a `Cursor` stands in for the socket).
/// Exposed only under the `fuzzing` feature so the normal build keeps the parser crate-private. The
/// reader takes fully untrusted client input, so a panic here is a remote DoS; the fuzzer hunts them.
#[cfg(feature = "fuzzing")]
pub fn fuzz_read_request(data: &[u8]) {
    let _ = wire::read_request(&mut std::io::Cursor::new(data));
}

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
    /// The per-chain fee-scanner state (design 0013), updated by the scanner threads and read by
    /// GET /status. Present (default, empty) even when no scanner runs, so /status always has the
    /// fields. Scan-only: these are counts and sats, never a key.
    scan_btc: Arc<Mutex<feescan::State>>,
    scan_xbtc: Arc<Mutex<feescan::State>>,
    /// An exclusive OS lock on the data dir, held for the daemon's whole life (design 0004). Two
    /// daemons on one seed and state would reuse per-swap key indices and secrets and double-broadcast,
    /// losing funds; this makes a second daemon on the same data dir refuse to start. Never read after
    /// `open`; it exists only to hold the lock until the file is dropped (daemon shutdown or exit).
    #[allow(dead_code)]
    _state_lock: File,
}

impl Daemon {
    /// Opens the daemon in `data_dir`: loads `settings.json` (or defaults), loads or creates the API
    /// token (`token`, mode 600).
    pub fn open(data_dir: &Path) -> std::io::Result<Daemon> {
        std::fs::create_dir_all(data_dir)?;
        // Single-writer guard (design 0004): take an exclusive, non-blocking lock on a lockfile in the
        // data dir and hold it for the daemon's life. A second daemon on the same seed and state would
        // reuse key indices and secrets and double-broadcast, which can lose funds, so refuse to start
        // rather than run two writers. The lock is advisory and released when the file is dropped or the
        // process exits (so a crash does not leave it stuck).
        let lock_path = data_dir.join("daemon.lock");
        let state_lock = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        match state_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!(
                        "another sovereign-swap daemon already holds the state lock at {}; \
                         two daemons on one seed would double-broadcast and risk losing funds \
                         (design 0004). Refusing to start.",
                        lock_path.display()
                    ),
                ));
            }
            Err(TryLockError::Error(e)) => return Err(e),
        }
        let settings: Settings = match std::fs::read(data_dir.join("settings.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Settings::default(),
        };
        // Config is owned by StartOS (the package action writes settings.json, which the daemon reads
        // here on each start). A malformed value cannot be fixed from the web UI, so surface it in the
        // log rather than failing silently; a blank default is not an error (just unconfigured).
        for issue in settings.validate() {
            eprintln!("settings issue: {issue}");
        }
        let token = load_or_make_token(data_dir)?;
        let basic_auth = match (
            std::env::var("SWAP_USERNAME"),
            std::env::var("SWAP_PASSWORD"),
        ) {
            (Ok(u), Ok(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
            _ => None,
        };
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
            scan_btc: Arc::new(Mutex::new(feescan::State::default())),
            scan_xbtc: Arc::new(Mutex::new(feescan::State::default())),
            _state_lock: state_lock,
        };
        // If the saved settings are already complete, bring the engine up. A failure here is not fatal
        // (the GUI learns it from GET /status), but it is logged: a silently swallowed reason is very
        // hard to diagnose in the field, where the nodes or the relay may be the cause.
        if let Err(e) = daemon.start_engine() {
            eprintln!("engine not started on open: {e}");
        }
        // Start the per-chain fee scanners for any chain configured with an SP fee address and a scan
        // key (design 0013). Independent of the engine: a scanner needs only the node, not a relay.
        daemon.start_scanners();
        Ok(daemon)
    }

    /// Opens the engine from the current settings and spawns its thread. Returns an error string if
    /// the settings are incomplete or a node or relay cannot be reached. Idempotent-ish: a running
    /// engine is replaced (the old thread ends when its channel drops).
    pub fn start_engine(&self) -> Result<(), String> {
        let settings = self.state.lock().unwrap().settings.clone();
        // Safety floor on the configurable minimum leg: the engine handles funds, so it must never
        // run with a `min_swap_sat` that would leave a leg unspendable after the claim/refund spend
        // fee. A sub-floor value is logged at open (so the GUI can surface it) and refused here, so
        // the bad value never reaches the engine; the daemon keeps serving `GET /status`.
        if settings.min_swap_sat < types::MIN_SWAP_FLOOR_SAT {
            return Err(format!(
                "min_swap_sat {} below the safety floor {} (claim/refund subtract the 2000 sat spend fee; the remainder must clear dust)",
                settings.min_swap_sat,
                types::MIN_SWAP_FLOOR_SAT
            ));
        }
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
        let tor_socks =
            resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &settings.tor_socks);
        // Per-chain funding mode (design 0012). Hot is unchanged: the node wallet signs. Cold opens a
        // watch-only funding wallet from the account descriptors and injects a `RemoteSigner` reached
        // over the same transport as a node; the signer is probed for reachability first, so the
        // daemon refuses to start rather than ever silently funding hot.
        let open_chain = |node_addr: &str,
                          node_user: &str,
                          node_pass: &str,
                          node_ca: &str,
                          funding: &FundingConfig,
                          chain: &'static str|
         -> Result<ChainNode, String> {
            let client = connect_client(node_addr, node_user, node_pass, node_ca, &tor_socks)
                .map_err(|e| format!("node {node_addr}: {e}"))?;
            match funding.mode {
                FundingMode::Hot => ChainNode::open(client, &wallet).map_err(|e| format!("{e:?}")),
                FundingMode::Cold => {
                    let signer_client = connect_client(
                        &funding.signer_endpoint,
                        &funding.signer_user,
                        &funding.signer_pass,
                        &funding.signer_ca,
                        &tor_socks,
                    )
                    .map_err(|e| format!("{chain} signer: {e}"))?
                    .with_timeout(SIGNER_TIMEOUT);
                    let signer = RemoteSigner::new(signer_client, chain);
                    signer
                        .probe()
                        .map_err(|e| format!("{chain} signer probe failed: {e:?}"))?;
                    ChainNode::open_cold(
                        client,
                        &wallet,
                        &funding.descriptor_receive,
                        &funding.descriptor_change,
                        Box::new(signer),
                    )
                    .map_err(|e| format!("{e:?}"))
                }
                // E2 (design 0017): a watch-only funding wallet as for cold, but the user signs out of
                // band. Funding parks the unsigned PSBT; the user submits it via /swaps/{id}/signed-psbt.
                FundingMode::Interactive => ChainNode::open_cold(
                    client,
                    &wallet,
                    &funding.descriptor_receive,
                    &funding.descriptor_change,
                    Box::new(InteractiveSigner),
                )
                .map_err(|e| format!("{e:?}")),
            }
        };
        let btc = open_chain(
            &settings.btc_node,
            &settings.btc_rpc_user,
            &settings.btc_rpc_pass,
            &settings.btc_rpc_ca,
            &settings.btc_funding,
            "btc",
        )?;
        let xbtc = open_chain(
            &settings.xbtc_node,
            &settings.xbtc_rpc_user,
            &settings.xbtc_rpc_pass,
            &settings.xbtc_rpc_ca,
            &settings.xbtc_funding,
            "xbtc",
        )?;
        let socks = relay.contains(".onion").then(|| tor_socks.to_owned());
        // Infallible by design (#113): a relay that is momentarily unreachable (a Tor-SOCKS race at
        // boot) must not stop the engine from starting and driving in-flight swaps. The connection's
        // worker attaches to the relay, and reconnects, asynchronously; /status shows the relay state.
        let conn = WsConn::connect(relay, socks.as_deref());
        let transport = RelayTransport::new(
            Identity::from_seed(&self.identity_seed),
            &self.routing_seed,
            conn,
        );
        let config = engine_config(&settings);
        let mut engine = Engine::open(&self.data_dir.join("engine"), btc, xbtc, transport, config)
            .map_err(|e| format!("engine: {e:?}"))?;
        engine.set_min_swap_sat(settings.min_swap_sat);
        engine.set_min_trade_sat(settings.min_trade_sat);
        engine.set_max_swap_sat(settings.max_swap_sat);
        // Take-side fee policy (security): refuse a taken offer whose taker fee exceeds our own cap, or
        // whose fee address for the chain we lock is not one we recognise. The offer's fee is set by
        // the maker, hostile on the public relay, so this stops a taker paying a large "fee" to an
        // attacker's address. The known set is our own per-chain addresses (single + rotating set).
        let known_fee = |single: &str, set: &[String]| -> Vec<String> {
            std::iter::once(single.trim().to_owned())
                .chain(set.iter().map(|a| a.trim().to_owned()))
                .filter(|a| !a.is_empty())
                .collect()
        };
        engine.set_fee_take_policy(
            crate::daemon::types::MAX_FEE_BPS,
            known_fee(&settings.fee_btc_address, &settings.fee_btc_addresses),
            known_fee(&settings.fee_xbtc_address, &settings.fee_xbtc_addresses),
        );
        // E1 (design 0016): when a chain has an Electrum endpoint configured, point its chain-data
        // reads and broadcasts at that server instead of the funding node's RPC. Empty leaves the
        // engine reading from the node, exactly as before. Funding and signing still use the node.
        for (chain, endpoint) in [
            (crate::swap::Chain::Btc, settings.btc_electrum.trim()),
            (crate::swap::Chain::Xbtc, settings.xbtc_electrum.trim()),
        ] {
            if endpoint.is_empty() {
                continue;
            }
            let (host, port) = endpoint
                .rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|port| (h, port)))
                .ok_or_else(|| format!("{chain:?} electrum endpoint not host:port: {endpoint}"))?;
            let socks = endpoint.contains(".onion").then(|| tor_socks.to_owned());
            let network = engine.node(chain).network();
            let backend = ElectrumBackend::connect(host, port, socks.as_deref(), network)
                .map_err(|e| format!("{chain:?} electrum {endpoint}: {e:?}"))?;
            engine.set_read_backend(chain, Box::new(backend));
        }

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

    /// Spawns one fee-scanner thread per chain configured with a silent payment fee address and a
    /// matching scan key (design 0013, stage 2). A chain with no scan key, or a normal fee address,
    /// is simply not scanned. A misconfigured scan key is logged (value-free) and skipped rather than
    /// starting a scanner that would find nothing. Each thread owns its own RPC client and persists
    /// its progress in the data dir, so it survives a restart without rescanning from the birthday.
    fn start_scanners(&self) {
        let settings = self.state.lock().unwrap().settings.clone();
        let tor_socks =
            resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &settings.tor_socks);
        let chains = [
            (
                "btc",
                &settings.btc_node,
                &settings.btc_rpc_user,
                &settings.btc_rpc_pass,
                &settings.btc_rpc_ca,
                &settings.fee_btc_address,
                settings.fee_btc_scan_key.as_str(),
                settings.fee_btc_birthday_height,
                Arc::clone(&self.scan_btc),
                "feescan-btc.json",
            ),
            (
                "xbtc",
                &settings.xbtc_node,
                &settings.xbtc_rpc_user,
                &settings.xbtc_rpc_pass,
                &settings.xbtc_rpc_ca,
                &settings.fee_xbtc_address,
                settings.fee_xbtc_scan_key.as_str(),
                settings.fee_xbtc_birthday_height,
                Arc::clone(&self.scan_xbtc),
                "feescan-xbtc.json",
            ),
        ];
        for (label, addr, user, pass, ca, fee_addr, scan_key, birthday, shared, file) in chains {
            let cfg = match feescan::ScanConfig::new(fee_addr, scan_key, birthday) {
                Ok(None) => continue, // not configured to scan this chain
                Ok(Some(cfg)) => cfg,
                Err(e) => {
                    eprintln!("fee-scanner {label}: not started: {e}");
                    continue;
                }
            };
            match connect_client(addr, user, pass, ca, &tor_socks) {
                Ok(client) => {
                    let state_file = self.data_dir.join(file);
                    eprintln!("fee-scanner {label}: started (birthday {})", cfg.birthday);
                    std::thread::spawn(move || {
                        feescan::run(label, client, cfg, state_file, shared)
                    });
                }
                Err(e) => eprintln!("fee-scanner {label}: not started: {e}"),
            }
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Binds and serves forever on `bind`. A thread per connection. Refuses an off-loopback bind with
    /// no web password set (see `serve_guard`): the page carries the API token.
    pub fn serve(self, bind: &str) -> std::io::Result<()> {
        // Fail closed. GET / serves the page with the API token substituted in, and that page is only
        // behind HTTP Basic auth when a web password is set. Off loopback with no password, the token
        // would be readable by anyone who can reach the port, which is full fund-touching API access.
        // Refuse to start in that case rather than serve an open API. On loopback the open page is
        // only reachable locally, so it is allowed (the plain non-StartOS daemon).
        serve_guard(bind, self.basic_auth.is_some())?;
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

    /// Bound on concurrent API connections. This is a single-user local API, so a handful of
    /// connections is the norm and this is generous headroom; its purpose is to stop a flood (over
    /// the onion, every connection arrives from the Tor proxy, so per-client limiting is impossible)
    /// from spawning unbounded threads and exhausting memory. The relay server has the same guard.
    const MAX_CONNECTIONS: usize = 128;

    fn accept_loop(self, listener: TcpListener) {
        let me = Arc::new(self);
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for stream in listener.incoming().flatten() {
            // At capacity, drop the connection without spawning a thread: a connection flood cannot
            // exhaust threads or memory, and a legitimate client simply retries. Accepting then
            // closing is cheaper than the work a served request would do.
            if active.load(std::sync::atomic::Ordering::Relaxed) >= Self::MAX_CONNECTIONS {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let me = Arc::clone(&me);
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                me.serve_connection(stream);
                active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
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
                    let page = INDEX_HTML
                        .replace("__TOKEN__", &self.token)
                        .replace("__VERSION__", env!("CARGO_PKG_VERSION"));
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
            ("GET", "/offers") => self.get_offers(),
            ("POST", "/offers") => self.post_offer(&req.body),
            ("GET", "/swaps") => self.get_swaps(),
            ("GET", "/history") => self.get_history(),
            ("POST", p)
                if p.starts_with("/offers/")
                    && p.ends_with("/take")
                    && valid_id(offer_id_of(p)) =>
            {
                self.post_take(offer_id_of(p), &req.body)
            }
            ("POST", p)
                if p.starts_with("/offers/")
                    && p.ends_with("/withdraw")
                    && valid_id(path_id(p, "/offers/", "/withdraw")) =>
            {
                self.post_withdraw(path_id(p, "/offers/", "/withdraw"))
            }
            ("POST", p)
                if p.starts_with("/swaps/")
                    && p.ends_with("/abort")
                    && valid_id(path_id(p, "/swaps/", "/abort")) =>
            {
                self.post_abort(path_id(p, "/swaps/", "/abort"))
            }
            ("POST", p)
                if p.starts_with("/swaps/")
                    && p.ends_with("/signed-psbt")
                    && valid_id(path_id(p, "/swaps/", "/signed-psbt")) =>
            {
                self.post_signed_psbt(path_id(p, "/swaps/", "/signed-psbt"), &req.body)
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
        let settings = self.state.lock().unwrap().settings.clone();
        if !settings.price_reference {
            return (200, json!({ "enabled": false }));
        }
        // The reference must dial the same Tor proxy as the engine (SWAP_TOR_SOCKS, else the
        // setting), not a hardcoded default: on StartOS the proxy is at an injected address.
        let socks = resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &settings.tor_socks);
        match self.reference.get(&settings.relays, &socks) {
            Ok((r, via)) => {
                let source = match via {
                    crate::daemon::reference::RateVia::Relay => "nonkyc BTCB2/BTC, via relay (Tor)",
                    crate::daemon::reference::RateVia::Direct => "nonkyc BTCB2/BTC, direct (Tor)",
                };
                (
                    200,
                    json!({
                        "enabled": true,
                        "rate": r.rate, "bid": r.bid, "ask": r.ask,
                        "source": source,
                        "verify_url": "https://nonkyc.io/market/BTCB2_BTC",
                    }),
                )
            }
            Err(e) => (200, json!({ "enabled": true, "error": e })),
        }
    }

    fn status(&self) -> Value {
        let settings = self.state.lock().unwrap().settings.clone();
        let running = self.engine_running();
        let active_swaps = if running {
            match self.engine_call::<Vec<SwapView>>(EngineCmd::Swaps) {
                Ok(swaps) => json!(swaps.iter().filter(|s| s.is_active()).count()),
                // The engine is up but did not answer (busy or timed out): report that it could not
                // be read, not a misleading zero that once hid an armed, fund-retrying maker.
                Err(_) => serde_json::Value::Null,
            }
        } else {
            json!(0)
        };
        // Fee scanner totals, per chain (design 0013, scan-only): how many fee outputs the operator
        // has collected and their total sats. Zero and present even when no scanner runs.
        let btc_scan = self.scan_btc.lock().unwrap().clone();
        let xbtc_scan = self.scan_xbtc.lock().unwrap().clone();
        json!({
            "btc_node": reachable(&settings.btc_node),
            "xbtc_node": reachable(&settings.xbtc_node),
            "relays": settings.relays.len(),
            "engine": running,
            "active_swaps": active_swaps,
            // Per-chain explorer bases for the web UI to link txids (#67); empty = render as plain text.
            "btc_explorer_url": settings.btc_explorer_url,
            "xbtc_explorer_url": settings.xbtc_explorer_url,
            // Fee scanner totals, per chain (design 0013, scan-only): outputs collected and total sats.
            "fees_found_btc": btc_scan.count(),
            "fees_sat_btc": btc_scan.sats(),
            "fees_found_xbtc": xbtc_scan.count(),
            "fees_sat_xbtc": xbtc_scan.sats(),
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
                json!(offers
                    .iter()
                    .map(|(o, seen_at)| offer_to_json(o, *seen_at))
                    .collect::<Vec<_>>()),
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

    /// The operator reporting ledger (#67): per-swap history plus totals, derived from the engine's
    /// own records. The web UI pairs the txids here with the configured explorer URLs (from
    /// `GET /status`) to render links.
    fn get_history(&self) -> (u16, Value) {
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(EngineCmd::History) {
            Ok(v) => (200, v),
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

    fn post_withdraw(&self, offer_id_hex: &str) -> (u16, Value) {
        let Ok(offer_id) = <[u8; 16]>::from_hex(offer_id_hex) else {
            return (400, json!({"error": "bad offer id"}));
        };
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(move |reply| EngineCmd::Withdraw { offer_id, reply }) {
            Ok(Ok(())) => (
                200,
                json!({ "withdrawn": offer_id.to_hex_string(Case::Lower) }),
            ),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn post_abort(&self, swap_id_hex: &str) -> (u16, Value) {
        let Ok(swap_id) = <[u8; 16]>::from_hex(swap_id_hex) else {
            return (400, json!({"error": "bad swap id"}));
        };
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(move |reply| EngineCmd::Abort { swap_id, reply }) {
            Ok(Ok(())) => (
                200,
                json!({ "aborted": swap_id.to_hex_string(Case::Lower) }),
            ),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    /// E2 (design 0017): the user submits the signed funding PSBT for a swap parked awaiting it. The
    /// engine validates it is the same transaction, finalizes, broadcasts, and the swap proceeds.
    fn post_signed_psbt(&self, swap_id_hex: &str, body: &[u8]) -> (u16, Value) {
        let Ok(swap_id) = <[u8; 16]>::from_hex(swap_id_hex) else {
            return (400, json!({"error": "bad swap id"}));
        };
        #[derive(Deserialize)]
        struct Submit {
            psbt: String,
        }
        let Ok(submit) = serde_json::from_slice::<Submit>(body) else {
            return (
                400,
                json!({"error": "expected a JSON object with a base64 psbt field"}),
            );
        };
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(move |reply| EngineCmd::SubmitSignedLock {
            swap_id,
            psbt: submit.psbt,
            reply,
        }) {
            Ok(Ok(())) => (200, json!({ "funded": swap_id.to_hex_string(Case::Lower) })),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn post_offer(&self, body: &[u8]) -> (u16, Value) {
        let Ok(new) = serde_json::from_slice::<NewOffer>(body) else {
            return (400, json!({"error": "offer must be a valid JSON object"}));
        };
        let (min_swap_sat, max_swap_sat) = {
            let s = &self.state.lock().unwrap().settings;
            (s.min_swap_sat, s.max_swap_sat)
        };
        let errors = new.validate(min_swap_sat, max_swap_sat);
        if !errors.is_empty() {
            return (422, json!({"error": "invalid offer", "fields": errors}));
        }
        if !self.engine_running() {
            return Self::not_running();
        }
        // F3 local band: refuse to publish an offer whose own voluntary fee would be a
        // disproportionate fraction of the leg. Local only; cannot fire under today's constants.
        {
            let guard = self.state.lock().unwrap();
            let s = &guard.settings;
            let addr = s.current_fee_address(new.sell_chain);
            if s.fee_enabled && addr.is_some() {
                let rates = crate::fee::FeeRates {
                    maker_bps: s.fee_maker_bps,
                    taker_bps: s.fee_taker_bps,
                };
                let leg = Amount::from_sat(new.amount_sat);
                if let Ok(fee) = crate::fee::fee_amount_min(
                    rates,
                    crate::swap::Role::Maker,
                    leg,
                    s.min_trade_sat,
                ) {
                    if crate::fee::fee_exceeds_band(fee, leg) {
                        return (
                            422,
                            json!({"error": format!(
                                "voluntary fee ({} sat) would exceed {}% of the {}-sat leg",
                                fee.to_sat(),
                                crate::fee::MAX_FEE_FRACTION_BPS / 100,
                                new.amount_sat
                            )}),
                        );
                    }
                }
            }
        }
        let offer = new.into_swap_offer(&self.state.lock().unwrap().settings);
        let id = offer.id.to_hex_string(Case::Lower);
        match self.engine_call(move |reply| EngineCmd::Publish(offer, reply)) {
            Ok(Ok(())) => (200, json!({ "offer_id": id })),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }
}

/// The Tor SOCKS proxy to dial through: `SWAP_TOR_SOCKS` wins when set and non-empty (StartOS
/// injects the proxy bridge address there, as its container has no Tor at a fixed address),
/// otherwise the `tor_socks` setting. Pure (the env value is passed in) so it is testable without
/// touching process-global state. The node RPC, the relay, and the price reference all resolve the
/// proxy this one way, so none of them can target a stale default the others do not.
fn resolve_tor_socks(env: Option<String>, setting: &str) -> String {
    env.filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| setting.to_owned())
}

/// Builds an RPC client for a node or a cold signer endpoint, applying the design-0011 transport
/// rules: an `.onion` is dialed through `tor_socks`, an `https` LAN address is verified against its
/// Root CA, plain `http` is direct. A node and a signer share this one builder (design 0012), so a
/// signer endpoint reaches the engine the same way a node does, with no new network code. The fee
/// scanner (design 0013) reaches a node through it too.
fn connect_client(
    addr: &str,
    user: &str,
    pass: &str,
    ca: &str,
    tor_socks: &str,
) -> Result<Client, String> {
    let socks = addr.contains(".onion").then_some(tor_socks);
    let ca = (!ca.trim().is_empty()).then_some(ca);
    Client::connect(addr, user, pass, ca, socks).map_err(|e| format!("{e:?}"))
}

/// True if `bind`'s host is a loopback address (reachable only from the same machine). `0.0.0.0` and
/// `::` bind all interfaces and are reachable off-host, so they are not loopback.
fn bind_is_loopback(bind: &str) -> bool {
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// Fail closed: an off-loopback bind with no web password would serve the API token (in GET /) to the
/// network. Returns an error so `serve` refuses to start rather than exposing a fund-touching API.
fn serve_guard(bind: &str, has_basic_auth: bool) -> std::io::Result<()> {
    if !bind_is_loopback(bind) && !has_basic_auth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to serve off-loopback with no web password set \
             (SWAP_USERNAME/SWAP_PASSWORD): GET / carries the API token and would be reachable by \
             anyone on the network",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bind_is_loopback, resolve_tor_socks, serve_guard};

    #[test]
    fn loopback_binds_are_recognised() {
        for b in ["127.0.0.1:8787", "localhost:8787", "::1:8787", "[::1]:8787"] {
            assert!(bind_is_loopback(b), "{b} should be loopback");
        }
        for b in ["0.0.0.0:8787", "203.0.113.1:8787", "::0:8787"] {
            assert!(!bind_is_loopback(b), "{b} should not be loopback");
        }
    }

    #[test]
    fn serve_guard_refuses_off_loopback_without_password() {
        // The dangerous combination: reachable off-host, no web password. Must refuse.
        assert!(serve_guard("0.0.0.0:8787", false).is_err());
        assert!(serve_guard("203.0.113.1:8787", false).is_err());
    }

    #[test]
    fn serve_guard_allows_the_safe_combinations() {
        // Off-loopback is fine with a password (the StartOS case).
        assert!(serve_guard("0.0.0.0:8787", true).is_ok());
        // Loopback is fine either way (reachable only locally).
        assert!(serve_guard("127.0.0.1:8787", false).is_ok());
        assert!(serve_guard("127.0.0.1:8787", true).is_ok());
    }

    #[test]
    fn tor_socks_env_overrides_the_setting() {
        // The injected env address wins, so the reference dials the same proxy as the engine.
        assert_eq!(
            resolve_tor_socks(Some("127.0.0.1:9150".to_owned()), "127.0.0.1:9050"),
            "127.0.0.1:9150"
        );
        // Absent or blank env falls back to the setting (the manual fallback).
        assert_eq!(resolve_tor_socks(None, "127.0.0.1:9050"), "127.0.0.1:9050");
        assert_eq!(
            resolve_tor_socks(Some("   ".to_owned()), "127.0.0.1:9050"),
            "127.0.0.1:9050"
        );
    }
}

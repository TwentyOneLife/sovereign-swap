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

use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash as _;
use bitcoin::hex::{Case, DisplayHex, FromHex};
use bitcoin::{Amount, PubkeyHash};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::electrum::ElectrumBackend;
use crate::engine::{Commitment, Engine};
use crate::envelope::Identity;
use crate::feescan;
use crate::htlc::PREIMAGE_LEN;
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

/// `scantxoutset` (the split address scan) walks the whole UTXO set. On the Blake2b chain, which
/// inherited Bitcoin's full pre-fork set (~167M txouts), that is mainnet-sized and runs well past the
/// default per-call `TIMEOUT` (120s), so the scan must get its own generous budget or it fails with a
/// read timeout (WouldBlock) every time (#199). A live measurement through the node's RPC proxy took
/// ~368s; 900s leaves margin for a loaded node. It is a read-only, operator-initiated call on one of
/// 128 connection slots, so a long bound is safe.
const SCAN_TIMEOUT: Duration = Duration::from_secs(900);

/// How long a finished (or stale) async scan job is kept before pruning (#206).
const SCAN_JOB_TTL: Duration = Duration::from_secs(1800);

/// An async coin-scan job (#206). `done` is `None` while the background thread runs, `Some(Ok(coins))`
/// when the scan + classify finished, `Some(Err(msg))` on failure. `coins` are the same JSON objects
/// the old synchronous scan returned.
struct ScanJob {
    address: String,
    started_at: std::time::Instant,
    done: Option<Result<Vec<Value>, String>>,
}

use engine::{
    engine_config, offer_to_json, run_engine, Dispatch, EngineCmd, ENGINE_CALL_TIMEOUT,
    ENGINE_CMD_DEADLINE,
};
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

/// Response headers that harden the embedded GUI: `frame-ancestors`/`X-Frame-Options` block framing
/// (clickjacking), the CSP pins every resource to this origin, and `base-uri`/`form-action` close the
/// base-tag and cross-origin-form vectors. `script-src 'self'` forbids inline scripts entirely: the
/// API token rides in a `<body data-token>` attribute (not an inline `<script>`) and the GUI uses
/// delegated listeners (no inline `onclick`), so no inline script is needed. `style-src` keeps
/// `'unsafe-inline'` for the GUI's inline style attributes; script injection, the real XSS risk, is
/// fully blocked. Each line ends in CRLF so it slots straight into the response header block.
const SECURITY_HEADERS: &str = "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\n";

/// Fuzz entry: run the HTTP request reader over arbitrary bytes (a `Cursor` stands in for the socket).
/// Exposed only under the `fuzzing` feature so the normal build keeps the parser crate-private. The
/// reader takes fully untrusted client input, so a panic here is a remote DoS; the fuzzer hunts them.
#[cfg(feature = "fuzzing")]
pub fn fuzz_read_request(data: &[u8]) {
    let _ = wire::read_request(&mut std::io::Cursor::new(data), None);
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
    engine: Arc<Mutex<Option<Sender<Dispatch>>>>,
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
    /// Coin-split service state (P5): the lent-marker pool + pending build jobs, persisted to
    /// `split.json`. A reserved marker or a built-but-unsubmitted job must survive a restart, else a
    /// restart could double-lend a marker.
    split: Arc<Mutex<crate::split::SplitState>>,
    /// In-flight async coin-scan jobs (#206): POST /split/scan runs scantxoutset + classify on a
    /// background thread (minutes on mainnet) so the request returns at once with a scan id, and the GUI
    /// polls GET /split/scan/{id}. In-memory only: a scan is cheap to re-run and need not survive a
    /// restart.
    scans: Arc<Mutex<HashMap<String, ScanJob>>>,
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
            split: Arc::new(Mutex::new(crate::split::SplitState::load(
                &data_dir.join("split.json"),
            ))),
            scans: Arc::new(Mutex::new(HashMap::new())),
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
        engine_call_on(&self.engine, make)
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

    /// Absolute wall-clock bound on reading one request (headers + body). A real client, even over Tor,
    /// delivers a small request in well under this; the purpose is to cut a slowloris that dribbles
    /// bytes to hold a connection slot forever (the `MAX_CONNECTIONS` cap alone does not help, since a
    /// per-read socket timeout is reset by every trickled byte). Over the onion every connection shares
    /// the Tor proxy source, so per-client limiting is impossible; a short, firm read deadline is the
    /// defence. Generous enough not to cut a slow Tor circuit delivering a 64 KB body.
    const REQUEST_READ_DEADLINE_SECS: u64 = 5;

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
        // A short per-read timeout so a stalled read wakes often enough to re-check the absolute
        // deadline below; the deadline, not this, is what bounds a slow-drip (slowloris) connection.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let req = match read_request(
            &mut stream,
            Some(Instant::now() + Duration::from_secs(Self::REQUEST_READ_DEADLINE_SECS)),
        ) {
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
             Connection: close\r\nX-Content-Type-Options: nosniff\r\n{SECURITY_HEADERS}\r\n",
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
            ("GET", "/my-offers") => self.get_my_offers(),
            ("POST", "/offers") => self.post_offer(&req.body),
            ("GET", "/swaps") => self.get_swaps(),
            ("GET", "/history") => self.get_history(),
            ("POST", "/split/classify") => self.split_classify(&req.body),
            ("POST", "/split/scan") => self.split_scan(&req.body),
            ("GET", p) if p.starts_with("/split/scan/") => {
                self.get_scan(&p["/split/scan/".len()..])
            }
            ("POST", "/split/verify") => self.split_verify(&req.body),
            ("POST", "/split/build") => self.split_build(&req.body),
            ("POST", "/split/submit") => self.split_submit(&req.body),
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
            ("POST", p)
                if p.starts_with("/swaps/")
                    && p.ends_with("/signed-spend")
                    && valid_id(path_id(p, "/swaps/", "/signed-spend")) =>
            {
                self.post_signed_spend(path_id(p, "/swaps/", "/signed-spend"), &req.body)
            }
            ("POST", "/commitments") => self.post_commitments(&req.body),
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
                        // The operator's pricing band (design 0025), so the Create-offer form can show
                        // the allowed range and keep the margin stepper inside it.
                        "price_band_pct": settings.price_band_pct,
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

    /// The maker's own live offers (#211), so the UI can list them with a Withdraw button. Distinct
    /// from GET /offers, which is the market (other peers' offers, with our own filtered out).
    fn get_my_offers(&self) -> (u16, Value) {
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(EngineCmd::OwnOffers) {
            Ok(offers) => (
                200,
                json!(offers
                    .iter()
                    .map(|o| offer_to_json(o, None))
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
            Ok(mut v) => {
                // Unified ledger (#218): add split operations as a `splits` array (newest first). Swap
                // entries carry no `kind`; split entries carry `kind:"split"`, so the GUI can render both
                // in one History table. Splits are daemon-local state, not the engine's.
                let splits: Vec<Value> = {
                    let st = self.split.lock().unwrap();
                    st.history()
                        .iter()
                        .rev()
                        .map(|r| {
                            json!({
                                "kind": "split",
                                "txid": r.txid,
                                "time": r.time,
                                "protected_sat": r.protected_sat,
                                "fee_sat": r.fee_sat,
                                "inputs": r.inputs,
                                "dest": r.dest,
                            })
                        })
                        .collect()
                };
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("splits".to_owned(), json!(splits));
                }
                (200, v)
            }
            Err(e) => (503, json!({ "error": e })),
        }
    }

    /// Coin-split service (P5), read-only: classify a UTXO on the Blake2b chain as a pre-fork
    /// **SHA-Coin** (exists on both chains, replayable, needs splitting) or a post-fork
    /// **Blake2b-Coin** (chain-specific). Moves nothing; it only reads the Blake2b node. Body:
    /// `{"txid": "...", "vout": N}`. The money-moving steps (build the separating PSBT, verify
    /// separation on the SHA256 node) are separate endpoints.
    fn split_classify(&self, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return (400, json!({"error": "body must be JSON"}));
        };
        let Some(txid) = req["txid"].as_str() else {
            return (422, json!({"error": "txid required"}));
        };
        let vout = req["vout"].as_u64().unwrap_or(0);
        // Snapshot the node config, then release the state lock before any network I/O.
        let (node, user, pass, ca, tor_socks, fork_height) = {
            let s = &self.state.lock().unwrap().settings;
            (
                s.xbtc_node.clone(),
                s.xbtc_rpc_user.clone(),
                s.xbtc_rpc_pass.clone(),
                s.xbtc_rpc_ca.clone(),
                resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                s.split_fork_height,
            )
        };
        let client = match connect_client(&node, &user, &pass, &ca, &tor_socks) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("Blake2b node: {e}")})),
        };
        let src = match crate::split::NodeTxSource::new(&client) {
            Ok(s) => s,
            Err(e) => return (502, json!({"error": e.to_string()})),
        };
        match crate::split::classify(&src, fork_height, txid, crate::split::DEFAULT_MAX_LOOKUPS) {
            Ok(kind) => (
                200,
                json!({
                    "txid": txid,
                    "vout": vout,
                    "kind": match kind {
                        crate::split::CoinKind::ShaCoin => "sha_coin",
                        crate::split::CoinKind::Blake2bCoin => "blake2b_coin",
                    },
                    "needs_split": kind.needs_split(),
                }),
            ),
            // A -5 "no such transaction" on the first fetch means the coin is not on the Blake2b chain
            // at all (#200): the user pasted a post-fork chain-exclusive coin or a wrong txid. That is
            // an ineligible input, not a node fault, so return a plain-language 422 instead of leaking
            // the raw RPC error. (classify needs a synced txindex; if the coin is genuinely a pre-fork
            // one, a -5 would instead mean the node's txindex is not caught up, noted in the message.)
            Err(crate::split::SplitError::Rpc(crate::rpc::RpcError::Rpc { code: -5, .. })) => (
                422,
                json!({"error": "this transaction is not found on the Blake2b chain, so it has no pre-fork counterpart to protect: only a pre-fork coin (present on both chains) needs separating. If you expected it here, check the txid is a Blake2b-chain coin and that the node's txindex is synced."}),
            ),
            Err(e) => (502, json!({"error": e.to_string()})),
        }
    }

    /// Coin-split service (P5), read-only: verify that a Blake2b **separating** transaction has
    /// actually separated the coin - it is confirmed deep enough on the Blake2b chain AND at least one
    /// of its inputs does not exist on the SHA256 chain, so the transaction can never be replayed there.
    /// Only a genuine "not found" (RPC code -5) on the SHA256 node counts an input as absent; any
    /// transport error is surfaced as "could not verify", NEVER as "separated" (a false "separated"
    /// would wrongly tell the operator the SHA256 side is safe to spend). Body: `{"txid": "..."}`.
    fn split_verify(&self, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return (400, json!({"error": "body must be JSON"}));
        };
        let Some(txid) = req["txid"].as_str() else {
            return (422, json!({"error": "txid required"}));
        };
        // Snapshot both nodes' config, then release the state lock before network I/O.
        let (xn, xu, xp, xca, bn, bu, bp, bca, tor) = {
            let s = &self.state.lock().unwrap().settings;
            (
                s.xbtc_node.clone(),
                s.xbtc_rpc_user.clone(),
                s.xbtc_rpc_pass.clone(),
                s.xbtc_rpc_ca.clone(),
                s.btc_node.clone(),
                s.btc_rpc_user.clone(),
                s.btc_rpc_pass.clone(),
                s.btc_rpc_ca.clone(),
                resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
            )
        };
        let xbtc = match connect_client(&xn, &xu, &xp, &xca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("Blake2b node: {e}")})),
        };
        let tx = match xbtc.call("getrawtransaction", json!([txid, true])) {
            Ok(v) => v,
            Err(e) => {
                return (
                    502,
                    json!({"error": format!("Blake2b getrawtransaction: {e:?}")}),
                )
            }
        };
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let inputs: Vec<(String, u32)> = tx["vin"]
            .as_array()
            .map(|vin| {
                vin.iter()
                    .filter_map(|i| {
                        Some((i["txid"].as_str()?.to_owned(), i["vout"].as_u64()? as u32))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if inputs.is_empty() {
            return (
                422,
                json!({"error": "not a spendable transaction (no inputs)"}),
            );
        }
        let btc = match connect_client(&bn, &bu, &bp, &bca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("SHA256 node: {e}")})),
        };
        // Safety gate: without a synced txindex the SHA256 node returns -5 for every confirmed tx not in
        // its mempool, which would make a replayable input look absent and the move look separated. Refuse
        // rather than risk a false "safe to spend".
        if let Err(e) = crate::split::require_txindex(&btc) {
            return (502, json!({"error": format!("cannot verify: {e}")}));
        }
        // Exists on SHA256 iff getrawtransaction succeeds; a genuine -5 means absent; anything else is a
        // real error we must not misread as absence. Shared with the regtest test.
        let exists = |t: &str| crate::split::exists_on_node(&btc, t);
        match crate::split::verify_separation(&inputs, confirmations, exists) {
            Ok(sep) => (
                200,
                json!({
                    "txid": txid,
                    "separated": sep.separated,
                    "confirmations": sep.confirmations,
                    "deep_enough": sep.deep_enough,
                    "final": sep.is_final(),
                    "sha256_only_input": sep.sha256_only_input,
                    "min_confirmations": crate::split::MIN_SEPARATION_CONFIRMATIONS,
                }),
            ),
            Err(e) => (
                502,
                json!({"error": format!("could not verify on the SHA256 node: {e}")}),
            ),
        }
    }

    /// Coin-split service: list the coins at a BTC (SHA256) address and classify each, so a user can give
    /// an address instead of a specific coin. Body `{"address":"..."}`. Uses `scantxoutset` on the
    /// Blake2b node (the shared pre-fork UTXOs live there too); that scans the UTXO set and can take a
    /// while. Returns each coin as `{txid, vout, value_sat, kind, needs_split}`; the pre-fork ones (kind
    /// `sha_coin`, `needs_split` true) are the ones to protect. The actual split still builds from a
    /// specific coin (`/split/build`); this only resolves an address to its coins.
    fn split_scan(&self, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return (400, json!({"error": "body must be JSON"}));
        };
        let Some(address) = req["address"].as_str() else {
            return (422, json!({"error": "address required"}));
        };
        let (xn, xu, xp, xca, tor, fork_height) = {
            let s = &self.state.lock().unwrap().settings;
            (
                s.xbtc_node.clone(),
                s.xbtc_rpc_user.clone(),
                s.xbtc_rpc_pass.clone(),
                s.xbtc_rpc_ca.clone(),
                resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                s.split_fork_height,
            )
        };
        let xbtc = match connect_client(&xn, &xu, &xp, &xca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("Blake2b node: {e}")})),
        };
        let network = match net_of(&xbtc) {
            Ok(n) => n,
            Err(e) => return (502, json!({"error": e})),
        };
        if address
            .parse::<bitcoin::Address<_>>()
            .ok()
            .and_then(|a| a.require_network(network).ok())
            .is_none()
        {
            return (422, json!({"error": "not a valid address for this chain"}));
        }
        // classify reads getrawtransaction, so the Blake2b node needs a synced txindex.
        if crate::split::require_txindex(&xbtc).is_err() {
            return (
                502,
                json!({"error": "the Blake2b node needs a synced txindex to classify coins"}),
            );
        }
        // scantxoutset walks the whole (mainnet-sized) UTXO set and classify reads a tx per coin, which
        // takes minutes (#199). Run it on a background thread (#206) so the request returns at once with
        // a scan id; the GUI polls GET /split/scan/{id}. The fast checks above (address, txindex) have
        // already run, so the job only fails on a transport error, surfaced through the job status.
        let address = address.to_owned();
        let scan_id = new_job_id();
        {
            let mut jobs = self.scans.lock().unwrap();
            jobs.retain(|_, j| j.done.is_none() || j.started_at.elapsed() < SCAN_JOB_TTL);
            jobs.insert(
                scan_id.clone(),
                ScanJob {
                    address: address.clone(),
                    started_at: Instant::now(),
                    done: None,
                },
            );
        }
        let scans = Arc::clone(&self.scans);
        let id = scan_id.clone();
        std::thread::spawn(move || {
            let result = scan_address(&xn, &xu, &xp, &xca, &tor, fork_height, &address);
            if let Some(job) = scans.lock().unwrap().get_mut(&id) {
                job.done = Some(result);
            }
        });
        (202, json!({ "scan_id": scan_id, "status": "scanning" }))
    }

    /// Poll an async coin-scan job (#206): `{status:"scanning"}` while it runs, `{status:"done", coins}`
    /// when finished, `{status:"error", error}` on failure, or 404 for an unknown or expired id.
    fn get_scan(&self, scan_id: &str) -> (u16, Value) {
        let jobs = self.scans.lock().unwrap();
        match jobs.get(scan_id) {
            None => (404, json!({"error": "unknown or expired scan"})),
            Some(j) => match &j.done {
                None => (200, json!({"status": "scanning", "address": j.address})),
                Some(Ok(coins)) => (
                    200,
                    json!({"status": "done", "address": j.address, "coins": coins}),
                ),
                Some(Err(e)) => (200, json!({"status": "error", "error": e})),
            },
        }
    }

    /// Coin-split service (P5): build the UNSIGNED separating PSBT for the lent-marker move. Body
    /// `{"sha_coins":[{"txid","vout"}...],"dest":"<Blake2b address>"}`. Reserves a marker (auto-scanning
    /// the swap wallet's Blake2b-Coins when the pool is empty), builds the PSBT with the user's
    /// SHA-Coin(s) + our lent marker, persists the exact transaction as a job, and returns it to sign.
    /// We co-sign the marker only at `/split/submit`, after checking the signed tx is the one we built.
    fn split_build(&self, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return (400, json!({"error": "body must be JSON"}));
        };
        let Some(dest_str) = req["dest"].as_str() else {
            return (422, json!({"error": "dest required"}));
        };
        let coins: Vec<(String, u32)> = req["sha_coins"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| {
                        Some((c["txid"].as_str()?.to_owned(), c["vout"].as_u64()? as u32))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if coins.is_empty() {
            return (422, json!({"error": "sha_coins required"}));
        }
        let (xn, xu, xp, xca, bn, bu, bp, bca, tor, fee_cfg, fork_height, wallet_name) = {
            let s = &self.state.lock().unwrap().settings;
            (
                s.xbtc_node.clone(),
                s.xbtc_rpc_user.clone(),
                s.xbtc_rpc_pass.clone(),
                s.xbtc_rpc_ca.clone(),
                s.btc_node.clone(),
                s.btc_rpc_user.clone(),
                s.btc_rpc_pass.clone(),
                s.btc_rpc_ca.clone(),
                resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                s.current_fee_address(Chain::Xbtc),
                s.split_fork_height,
                format!(
                    "swap-{}",
                    self.identity_seed[..4].to_hex_string(Case::Lower)
                ),
            )
        };
        let Some(fee_cfg) = fee_cfg else {
            return (503, json!({"error": "no XBT fee address configured"}));
        };
        let xbtc = match connect_client(&xn, &xu, &xp, &xca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("Blake2b node: {e}")})),
        };
        let btc = match connect_client(&bn, &bu, &bp, &bca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("SHA256 node: {e}")})),
        };
        if let Err(e) = crate::split::require_txindex(&btc) {
            return (502, json!({"error": format!("SHA256 node: {e}")}));
        }
        let network = match net_of(&xbtc) {
            Ok(n) => n,
            Err(e) => return (502, json!({"error": e})),
        };
        let parse_addr = |s: &str| -> Option<bitcoin::Address> {
            s.parse::<bitcoin::Address<_>>()
                .ok()
                .and_then(|a| a.require_network(network).ok())
        };
        let Some(dest) = parse_addr(dest_str) else {
            return (
                422,
                json!({"error": "dest is not a valid address for this chain"}),
            );
        };
        // The fee address must be a plain address: we cannot derive a silent-payment output without the
        // keys of every input, and in a two-owner move we hold only the marker's.
        let Some(fee_addr) = parse_addr(&fee_cfg) else {
            return (
                503,
                json!({"error": "the XBT fee address must be a plain address, not a silent-payment address"}),
            );
        };
        let wallet = xbtc.wallet(&wallet_name);
        let now = unix_now();

        // Reserve a marker, auto-scanning the wallet's Blake2b-Coins into the pool if none is free.
        let (job_id, marker) = {
            let mut st = self.split.lock().unwrap();
            st.expire(now, crate::split::MARKER_RESERVATION_SECS);
            let job_id = new_job_id();
            if st.pool.reserve(&job_id, now).is_none() {
                for u in list_unspent(&wallet) {
                    if st.pool.available_count() > 0 {
                        break;
                    }
                    let Ok(kind) = classify_on(&xbtc, fork_height, &u.0) else {
                        continue;
                    };
                    if kind != crate::split::CoinKind::Blake2bCoin {
                        continue;
                    }
                    if crate::split::verify_marker(&btc, &u.0).is_err() {
                        continue;
                    }
                    let _ = st.pool.add_marker(crate::split::Marker {
                        txid: u.0,
                        vout: u.1,
                        value_sat: u.2,
                    });
                }
                if st.pool.reserve(&job_id, now).is_none() {
                    return (
                        503,
                        json!({"error": "no lendable Blake2b-Coin marker available; fund the swap wallet"}),
                    );
                }
            }
            (job_id.clone(), st.pool.reserved_marker(&job_id).unwrap())
        };

        // Prepare inputs (kinds derived on-chain) and build. On any failure, release the reservation.
        let build = (|| -> Result<(String, u64, String, u64), (u16, Value)> {
            let mut prepared = Vec::new();
            for (txid, vout) in &coins {
                let p = crate::split::prepare_input(&xbtc, fork_height, txid, *vout)
                    .map_err(|e| (422, json!({"error": format!("input {txid}:{vout}: {e}")})))?;
                prepared.push(p);
            }
            prepared.push(
                crate::split::prepare_input(&xbtc, fork_height, &marker.txid, marker.vout)
                    .map_err(|e| (502, json!({"error": format!("marker: {e}")})))?,
            );
            let change_str = wallet
                .call("getnewaddress", json!(["", "bech32"]))
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or((502, json!({"error": "could not get a change address"})))?;
            let change =
                parse_addr(&change_str).ok_or((502, json!({"error": "bad change address"})))?;
            let net_fee = estimate_network_fee(&wallet, prepared.len());
            let psbt =
                crate::split::build_split_psbt(&prepared, &dest, &fee_addr, &change, net_fee)
                    .map_err(|e| (422, json!({"error": format!("{e}")})))?;
            let unsigned_hex = psbt_unsigned_hex(&psbt)
                .ok_or((500, json!({"error": "could not read built tx"})))?;
            let protected_sat: u64 = prepared
                .iter()
                .filter(|p| p.input.kind == crate::split::CoinKind::ShaCoin)
                .map(|p| p.input.value_sat)
                .sum();
            let fee_sat = crate::split::project_fee_sat(protected_sat, crate::split::FEE_BPS);
            Ok((psbt, fee_sat, unsigned_hex, protected_sat))
        })();
        let (psbt, fee_sat, unsigned_hex, protected_sat) = match build {
            Ok(v) => v,
            Err(err) => {
                let mut st = self.split.lock().unwrap();
                st.pool.release(&job_id);
                let _ = st.save(&self.data_dir.join("split.json"));
                return err;
            }
        };
        {
            let mut st = self.split.lock().unwrap();
            st.set_job(&job_id, unsigned_hex);
            // Park the display metadata (#218) so a successful submit becomes a History entry.
            st.set_meta(
                &job_id,
                crate::split::SplitMeta {
                    protected_sat,
                    fee_sat,
                    inputs: coins.iter().map(|(t, v)| format!("{t}:{v}")).collect(),
                    dest: dest_str.to_owned(),
                },
            );
            let _ = st.save(&self.data_dir.join("split.json"));
        }
        (
            200,
            json!({
                "job_id": job_id,
                "psbt": psbt,
                "fee_sat": fee_sat,
                "marker": {"txid": marker.txid, "vout": marker.vout},
            }),
        )
    }

    /// Coin-split service (P5): co-sign our marker on a user-signed split PSBT and broadcast it. Body
    /// `{"job_id":"...","psbt":"<base64>"}`. Validates the signed transaction is byte-for-byte the one we
    /// built for this job and that the user's inputs use an ALL-family sighash (never ANYONECANPAY), then
    /// co-signs ONLY the marker on the ORIGINAL base64 (so a 0x21 sighash byte is not rewritten),
    /// finalizes and broadcasts, and taints the recovered-marker change so it is never lent again.
    fn split_submit(&self, body: &[u8]) -> (u16, Value) {
        let Ok(req) = serde_json::from_slice::<Value>(body) else {
            return (400, json!({"error": "body must be JSON"}));
        };
        let (Some(job_id), Some(signed)) = (req["job_id"].as_str(), req["psbt"].as_str()) else {
            return (422, json!({"error": "job_id and psbt required"}));
        };
        let (expected, marker) = {
            let st = self.split.lock().unwrap();
            let Some(expected) = st.job(job_id).map(str::to_owned) else {
                return (410, json!({"error": "unknown or expired job"}));
            };
            let Some(marker) = st.pool.reserved_marker(job_id) else {
                return (410, json!({"error": "no marker reserved for this job"}));
            };
            (expected, marker)
        };
        let marker_out = match marker.txid.parse() {
            Ok(txid) => bitcoin::OutPoint {
                txid,
                vout: marker.vout,
            },
            Err(_) => return (500, json!({"error": "bad marker txid in state"})),
        };
        if let Err(e) = crate::split::validate_user_signed(&expected, signed, marker_out) {
            return (400, json!({"error": format!("{e}")}));
        }
        let (xn, xu, xp, xca, tor, wallet_name) = {
            let s = &self.state.lock().unwrap().settings;
            (
                s.xbtc_node.clone(),
                s.xbtc_rpc_user.clone(),
                s.xbtc_rpc_pass.clone(),
                s.xbtc_rpc_ca.clone(),
                resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                format!(
                    "swap-{}",
                    self.identity_seed[..4].to_hex_string(Case::Lower)
                ),
            )
        };
        let xbtc = match connect_client(&xn, &xu, &xp, &xca, &tor) {
            Ok(c) => c,
            Err(e) => return (502, json!({"error": format!("Blake2b node: {e}")})),
        };
        let wallet = xbtc.wallet(&wallet_name);
        // Co-sign the marker on the ORIGINAL base64 (never a re-serialized PSBT).
        let processed = match wallet.call("walletprocesspsbt", json!([signed])) {
            Ok(v) => v,
            Err(e) => return (502, json!({"error": format!("co-sign: {e:?}")})),
        };
        let Some(psbt2) = processed["psbt"].as_str() else {
            return (502, json!({"error": "co-sign returned no psbt"}));
        };
        let finalized = match wallet.call("finalizepsbt", json!([psbt2])) {
            Ok(v) => v,
            Err(e) => return (502, json!({"error": format!("finalize: {e:?}")})),
        };
        if finalized["complete"] != true {
            return (
                400,
                json!({"error": "not fully signed: sign your input before submitting"}),
            );
        }
        let Some(hex) = finalized["hex"].as_str() else {
            return (502, json!({"error": "finalize returned no tx"}));
        };
        let txid = match xbtc.call("sendrawtransaction", json!([hex])) {
            Ok(v) => v.as_str().unwrap_or_default().to_owned(),
            // Keep the job + reservation on a broadcast failure so the user can retry; it expires if
            // abandoned. The marker is committed in this exact tx, so a retry re-broadcasts the same one.
            Err(e) => return (502, json!({"error": format!("broadcast failed: {e:?}")})),
        };
        {
            // Broadcast accepted: the marker is spent and its recovered change is output of THIS tx, so
            // taint `txid` (finish_job) - the change can never be lent as a future marker.
            let mut st = self.split.lock().unwrap();
            st.finish_job(job_id, txid.clone());
            // Record the completed split in the History ledger (#218).
            st.record_submit(job_id, txid.clone(), unix_now());
            let _ = st.save(&self.data_dir.join("split.json"));
        }
        (200, json!({"txid": txid}))
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
        // Take-side market band check (design 0025: the "pre-take" half of the local checks). The
        // publish-time band check (post_offer) does not protect a TAKER: an offer may have been
        // published before #208, by a peer that does not enforce the band, or priced when the market
        // sat elsewhere, yet it still shows in /offers and stays takeable. Re-validate the offer's
        // implied price against THIS node's live reference and refuse an off-market take, so no swap
        // ever executes outside the band regardless of how the offer was posted. Liveness over the
        // feed: when the reference is off or unavailable, or the offer is not in view, we do not block
        // the take (mirrors post_offer, which only hard-requires a reference on the market-derived
        // publish path).
        {
            let (price_ref_on, band_pct, relays, tor_socks) = {
                let s = &self.state.lock().unwrap().settings;
                (
                    s.price_reference,
                    s.price_band_pct,
                    s.relays.clone(),
                    resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                )
            };
            if price_ref_on {
                if let Ok(offers) = self.engine_call(EngineCmd::Offers) {
                    if let Some((offer, _)) = offers.iter().find(|(o, _)| o.id == offer_id) {
                        // The offer carries the swap-layer Chain; pricing takes the daemon Chain.
                        let sell_chain = match offer.maker_chain {
                            crate::swap::Chain::Btc => Chain::Btc,
                            crate::swap::Chain::Xbtc => Chain::Xbtc,
                        };
                        let market = self
                            .reference
                            .get(&relays, &tor_socks)
                            .ok()
                            .and_then(|(r, _)| crate::pricing::market_price(sell_chain, r.rate));
                        if let Some(m) = market {
                            let price = offer.taker_amount.to_sat() as f64
                                / offer.maker_amount.to_sat() as f64;
                            if !crate::pricing::in_band(price, m, band_pct) {
                                let (lo, hi) = crate::pricing::band_range(m, band_pct);
                                return (
                                    422,
                                    json!({"error": format!(
                                        "offer price {price:.8} is outside {band_pct}% of the market rate {m:.8} (allowed {lo:.8}..{hi:.8}); the offer may be stale - refusing an off-market take"
                                    )}),
                                );
                            }
                        }
                    }
                }
            }
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

    /// 0027: the user submits their signature over a parked claim/refund's sighash (user-held spends).
    /// Body `{"sig":"<DER hex>","pubkey":"<compressed hex>"}`. The engine finalizes and broadcasts.
    fn post_signed_spend(&self, swap_id_hex: &str, body: &[u8]) -> (u16, Value) {
        let Ok(swap_id) = <[u8; 16]>::from_hex(swap_id_hex) else {
            return (400, json!({"error": "bad swap id"}));
        };
        #[derive(Deserialize)]
        struct Submit {
            sig: String,
            pubkey: String,
            /// 0027: the maker's secret (hex, 32 bytes), supplied by a user-held maker with its claim
            /// signature. Omitted for a refund or a taker claim.
            #[serde(default)]
            preimage: Option<String>,
        }
        let Ok(submit) = serde_json::from_slice::<Submit>(body) else {
            return (
                400,
                json!({"error": "expected a JSON object with hex sig and pubkey fields"}),
            );
        };
        let Ok(sig_bytes) = Vec::<u8>::from_hex(&submit.sig) else {
            return (400, json!({"error": "sig must be hex"}));
        };
        let Ok(sig) = bitcoin::secp256k1::ecdsa::Signature::from_der(&sig_bytes) else {
            return (
                400,
                json!({"error": "sig is not a valid DER ECDSA signature"}),
            );
        };
        let Ok(pub_bytes) = Vec::<u8>::from_hex(&submit.pubkey) else {
            return (400, json!({"error": "pubkey must be hex"}));
        };
        let Ok(pubkey) = bitcoin::PublicKey::from_slice(&pub_bytes) else {
            return (400, json!({"error": "pubkey is not a valid public key"}));
        };
        let preimage = match submit.preimage {
            None => None,
            Some(ref hex) => {
                let Ok(bytes) = Vec::<u8>::from_hex(hex) else {
                    return (400, json!({"error": "preimage must be hex"}));
                };
                let Ok(arr) = <[u8; PREIMAGE_LEN]>::try_from(bytes.as_slice()) else {
                    return (
                        400,
                        json!({"error": format!("preimage must be {PREIMAGE_LEN} bytes")}),
                    );
                };
                Some(arr)
            }
        };
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(move |reply| EngineCmd::SubmitSignedSpend {
            swap_id,
            sig,
            pubkey,
            preimage,
            reply,
        }) {
            Ok(Ok(())) => (200, json!({ "spent": swap_id.to_hex_string(Case::Lower) })),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    /// 0027: pre-provision user-held commitment bundles for upcoming swap indices. The body is a JSON
    /// array of `{index, secret_hash, claim_pkh, refund_pkh}` (hex), all PUBLIC data the browser
    /// derives from the user's own seed. The engine commits one per swap and never reuses it.
    fn post_commitments(&self, body: &[u8]) -> (u16, Value) {
        #[derive(Deserialize)]
        struct Entry {
            index: u32,
            secret_hash: String,
            claim_pkh: String,
            refund_pkh: String,
        }
        let Ok(entries) = serde_json::from_slice::<Vec<Entry>>(body) else {
            return (
                400,
                json!({"error": "expected a JSON array of {index, secret_hash, claim_pkh, refund_pkh} (hex)"}),
            );
        };
        let parse_pkh = |hex: &str| -> Option<PubkeyHash> {
            let bytes = Vec::<u8>::from_hex(hex).ok()?;
            PubkeyHash::from_slice(&bytes).ok()
        };
        let mut parsed = Vec::with_capacity(entries.len());
        for e in &entries {
            let Ok(sh_bytes) = Vec::<u8>::from_hex(&e.secret_hash) else {
                return (400, json!({"error": "secret_hash must be hex"}));
            };
            let Ok(secret_hash) = <[u8; 32]>::try_from(sh_bytes.as_slice()) else {
                return (400, json!({"error": "secret_hash must be 32 bytes"}));
            };
            let (Some(claim_pkh), Some(refund_pkh)) =
                (parse_pkh(&e.claim_pkh), parse_pkh(&e.refund_pkh))
            else {
                return (
                    400,
                    json!({"error": "claim_pkh and refund_pkh must be 20-byte hex pubkey hashes"}),
                );
            };
            parsed.push((
                e.index,
                Commitment {
                    secret_hash,
                    claim_pkh,
                    refund_pkh,
                },
            ));
        }
        if !self.engine_running() {
            return Self::not_running();
        }
        match self.engine_call(move |reply| EngineCmd::ProvisionCommitments {
            entries: parsed,
            reply,
        }) {
            Ok(Ok(())) => (200, json!({ "provisioned": entries.len() })),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn post_offer(&self, body: &[u8]) -> (u16, Value) {
        let Ok(mut new) = serde_json::from_slice::<NewOffer>(body) else {
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
        // Market-anchored pricing (design 0025): resolve the offer's price against the nonkyc reference
        // and refuse an off-market rate. Closes the 1:1 hole - a silent parity fallback, or a raw
        // off-market counter_amount_sat taken verbatim. Local check, like the F3 fee band; no wire
        // change. The market-derived path (no explicit price or counter) REQUIRES a live reference, so
        // automation can never post a parity offer by omission.
        {
            let (price_ref_on, band_pct, relays, tor_socks) = {
                let s = &self.state.lock().unwrap().settings;
                (
                    s.price_reference,
                    s.price_band_pct,
                    s.relays.clone(),
                    resolve_tor_socks(std::env::var("SWAP_TOR_SOCKS").ok(), &s.tor_socks),
                )
            };
            // The live market price for this direction (counter per unit sold), when the reference is
            // on and resolves; None when off or unavailable.
            let market = if price_ref_on {
                self.reference
                    .get(&relays, &tor_socks)
                    .ok()
                    .and_then(|(r, _)| crate::pricing::market_price(new.sell_chain, r.rate))
            } else {
                None
            };
            // The offer's implied price (counter per unit sold): an explicit counter or price verbatim,
            // else the market-derived path (market * (1 + margin_pct/100)), which needs a reference.
            let price = if let Some(counter) = new.counter_amount_sat {
                counter as f64 / new.amount_sat as f64
            } else if let Some(p) = new.price {
                p
            } else {
                match market {
                    Some(m) => crate::pricing::effective_price(m, new.margin_pct.unwrap_or(0)),
                    None => {
                        return (
                            503,
                            json!({"error": "market reference required to price an offer from the market rate (design 0025): enable the price reference, or give an explicit price or counter_amount_sat"}),
                        );
                    }
                }
            };
            // Band check against the market when we have one; an off-market offer is refused with range.
            if let Some(m) = market {
                if !crate::pricing::in_band(price, m, band_pct) {
                    let (lo, hi) = crate::pricing::band_range(m, band_pct);
                    return (
                        422,
                        json!({"error": format!(
                            "price {price:.8} is outside {band_pct}% of the market rate {m:.8} (allowed {lo:.8}..{hi:.8})"
                        )}),
                    );
                }
            }
            // Resolve to a concrete counter amount, floor-checked, and let into_swap_offer take it
            // verbatim (clear the price/margin inputs so only the resolved counter remains).
            let counter = new
                .counter_amount_sat
                .unwrap_or_else(|| crate::pricing::counter_from(new.amount_sat, price));
            if counter < min_swap_sat {
                return (
                    422,
                    json!({"error": format!(
                        "resolved counter_amount_sat ({counter}) is below the minimum leg ({min_swap_sat})"
                    )}),
                );
            }
            new.counter_amount_sat = Some(counter);
            new.price = None;
            new.margin_pct = None;
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

/// Sends one command to the engine thread and waits for its reply, holding the engine lock only for
/// the moment it takes to clone the command sender, never across the reply wait. The engine is a
/// single thread, so commands still serialize there; what this buys is that a slow or wedged reply
/// (up to the 10 s timeout) no longer holds the mutex. Lock-only checks (`engine_running`, the
/// publish pre-check) stay responsive, and N stalled calls each time out in parallel at ~10 s
/// instead of compounding. Free function (not a method) so it is unit-testable without a `Daemon`.
fn engine_call_on<R>(
    engine: &Mutex<Option<Sender<Dispatch>>>,
    make: impl FnOnce(Sender<R>) -> EngineCmd,
) -> Result<R, String> {
    let tx = {
        let guard = engine.lock().unwrap();
        guard.as_ref().ok_or("engine not running")?.clone()
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    let dispatch = Dispatch {
        cmd: make(reply_tx),
        deadline: Instant::now() + ENGINE_CMD_DEADLINE,
    };
    tx.send(dispatch).map_err(|_| "engine stopped")?;
    drop(tx); // release our clone before the wait; the engine keeps its own sender
    reply_rx.recv_timeout(ENGINE_CALL_TIMEOUT).map_err(|e| {
        match e {
            // The engine dropped the command without replying: it gated a stale Publish/Take (#176),
            // so the action definitely did not happen and retrying is safe.
            RecvTimeoutError::Disconnected => "not applied; safe to retry",
            // The engine is still busy and never replied in time: the action may or may not have run,
            // so the caller should check Swaps/Offers before retrying rather than blindly resend.
            RecvTimeoutError::Timeout => "outcome unknown; check Swaps and Offers before retrying",
        }
        .to_owned()
    })
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

/// The slow half of a coin scan (#206), run on a background thread: scantxoutset at `address`, then
/// classify each unspent. Returns the coin JSON objects the synchronous scan used to return, or an
/// error string. The caller has already validated the address and the node's txindex.
fn scan_address(
    xn: &str,
    xu: &str,
    xp: &str,
    xca: &str,
    tor: &str,
    fork_height: u32,
    address: &str,
) -> Result<Vec<Value>, String> {
    let xbtc = connect_client(xn, xu, xp, xca, tor).map_err(|e| format!("Blake2b node: {e}"))?;
    let scan = xbtc
        .clone()
        .with_timeout(SCAN_TIMEOUT)
        .call(
            "scantxoutset",
            json!(["start", [{"desc": format!("addr({address})")}]]),
        )
        .map_err(|e| format!("scan failed: {e:?}"))?;
    let src = crate::split::NodeTxSource::new(&xbtc).map_err(|e| e.to_string())?;
    let mut coins = Vec::new();
    for u in scan["unspents"].as_array().into_iter().flatten() {
        let (Some(txid), Some(vout)) = (u["txid"].as_str(), u["vout"].as_u64()) else {
            continue;
        };
        let value_sat = u["amount"]
            .as_f64()
            .map(|b| (b * 1e8).round() as u64)
            .unwrap_or(0);
        let Ok(kind) =
            crate::split::classify(&src, fork_height, txid, crate::split::DEFAULT_MAX_LOOKUPS)
        else {
            continue;
        };
        coins.push(json!({
            "txid": txid,
            "vout": vout,
            "value_sat": value_sat,
            "kind": match kind { crate::split::CoinKind::ShaCoin => "sha_coin", _ => "blake2b_coin" },
            "needs_split": kind.needs_split(),
        }));
    }
    Ok(coins)
}

/// Seconds since the Unix epoch (for marker-reservation timestamps).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A random split job id (8 bytes of /dev/urandom, hex).
fn new_job_id() -> String {
    use std::io::Read;
    let mut b = [0u8; 8];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    b.to_hex_string(Case::Lower)
}

/// The bitcoin `Network` a node serves, from `getblockchaininfo` (so addresses are parsed for the right
/// network).
fn net_of(rpc: &Client) -> Result<bitcoin::Network, String> {
    let info = rpc
        .call("getblockchaininfo", json!([]))
        .map_err(|e| format!("getblockchaininfo: {e:?}"))?;
    match info["chain"].as_str() {
        Some("main") => Ok(bitcoin::Network::Bitcoin),
        Some("test") => Ok(bitcoin::Network::Testnet),
        Some("signet") => Ok(bitcoin::Network::Signet),
        Some("regtest") => Ok(bitcoin::Network::Regtest),
        other => Err(format!("unknown network {other:?}")),
    }
}

/// A wallet's unspent outputs as (txid, vout, value_sat).
fn list_unspent(wallet: &Client) -> Vec<(String, u32, u64)> {
    wallet
        .call("listunspent", json!([1]))
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|u| {
            Some((
                u["txid"].as_str()?.to_owned(),
                u["vout"].as_u64()? as u32,
                (u["amount"].as_f64()? * 1e8).round() as u64,
            ))
        })
        .collect()
}

/// Classify a coin by its funding txid on the Blake2b node (for the marker auto-scan).
fn classify_on(
    xbtc: &Client,
    fork_height: u32,
    txid: &str,
) -> Result<crate::split::CoinKind, crate::split::SplitError> {
    let src = crate::split::NodeTxSource::new(xbtc)?;
    crate::split::classify(&src, fork_height, txid, crate::split::DEFAULT_MAX_LOOKUPS)
}

/// A rough network fee for the split: sat/vB from `estimatesmartfee` (fallback 1 sat/vB on a chain that
/// cannot estimate, e.g. regtest) times an estimated vsize, with a floor so a tiny estimate still clears.
fn estimate_network_fee(wallet: &Client, n_inputs: usize) -> u64 {
    let sat_vb = wallet
        .call("estimatesmartfee", json!([6]))
        .ok()
        .and_then(|v| v["feerate"].as_f64())
        .map(|btc_kvb| (btc_kvb * 1e8 / 1000.0).ceil() as u64)
        .filter(|&r| r > 0)
        .unwrap_or(1);
    let vsize = (n_inputs as u64) * 110 + 3 * 34 + 11;
    (sat_vb * vsize).max(1000)
}

/// The hex of a base64 PSBT's unsigned transaction (what `/split/submit` matches byte-for-byte).
fn psbt_unsigned_hex(psbt_b64: &str) -> Option<String> {
    use std::str::FromStr;
    bitcoin::Psbt::from_str(psbt_b64)
        .ok()
        .map(|p| bitcoin::consensus::encode::serialize_hex(&p.unsigned_tx))
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
    use super::{
        bind_is_loopback, engine_call_on, resolve_tor_socks, serve_guard, Dispatch, EngineCmd,
        ENGINE_CALL_TIMEOUT,
    };
    use std::sync::mpsc::{self, Sender};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[test]
    fn engine_call_does_not_hold_the_lock_across_the_reply_wait() {
        // Regression: engine_call_on must clone the command sender and release the engine lock
        // before it blocks waiting for the reply. If it held the guard across the wait (the old
        // behaviour), a slow engine reply would freeze every lock-only check (engine_running, the
        // publish pre-check) and serialize unrelated API calls. We prove the lock is free while a
        // call is parked in recv_timeout.
        let (eng_tx, eng_rx) = mpsc::channel::<Dispatch>();
        let engine: Arc<Mutex<Option<Sender<Dispatch>>>> = Arc::new(Mutex::new(Some(eng_tx)));

        let eng = Arc::clone(&engine);
        let (sent_tx, sent_rx) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            // Any variant carrying a reply Sender; Offers replies with a plain Vec.
            let r = engine_call_on(&eng, |reply| {
                sent_tx.send(()).unwrap(); // signal: command built, about to send then wait
                EngineCmd::Offers(reply)
            });
            r.unwrap()
        });

        // The caller has handed us its command and is now parked in recv_timeout.
        sent_rx.recv().unwrap();
        let d = eng_rx.recv().unwrap();

        // The command's deadline must be strictly before the caller's wait would expire, so a dropped
        // (gated) command disconnects the reply channel before the caller times out (#176).
        assert!(
            d.deadline < Instant::now() + ENGINE_CALL_TIMEOUT,
            "command deadline must be earlier than the caller's wait"
        );

        // The mutex must be free while the caller waits. Under the old code the caller still holds
        // the guard here and this try_lock returns WouldBlock, failing the test.
        assert!(
            engine.try_lock().is_ok(),
            "engine lock held across the reply wait"
        );

        // Reply so the caller returns promptly, then join.
        match d.cmd {
            EngineCmd::Offers(reply) => reply.send(Vec::new()).unwrap(),
            _ => panic!("expected Offers"),
        }
        let got = caller.join().unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn a_dropped_stale_command_returns_not_applied_at_once() {
        // When the engine gates a stale Publish/Take, it drops the Dispatch without replying, which
        // disconnects the reply channel. engine_call_on must surface that as the "not applied" case
        // promptly (not wait out the full timeout, not report an ambiguous "outcome unknown").
        let (eng_tx, eng_rx) = mpsc::channel::<Dispatch>();
        let engine: Arc<Mutex<Option<Sender<Dispatch>>>> = Arc::new(Mutex::new(Some(eng_tx)));
        let started = Instant::now();
        let caller = std::thread::spawn(move || engine_call_on(&engine, EngineCmd::Offers));
        // Receive and immediately drop the Dispatch (simulating the gate dropping a stale command).
        drop(eng_rx.recv().unwrap());
        let res = caller.join().unwrap();
        assert_eq!(res, Err("not applied; safe to retry".to_owned()));
        assert!(
            started.elapsed() < ENGINE_CALL_TIMEOUT,
            "a disconnected reply must return before the full timeout"
        );
    }

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

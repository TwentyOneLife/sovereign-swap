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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hex::{Case, DisplayHex};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
}

struct DaemonState {
    settings: Settings,
    offers: Vec<Offer>,
}

pub struct Daemon {
    state: Arc<Mutex<DaemonState>>,
    token: String,
    data_dir: PathBuf,
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
        Ok(Daemon {
            state: Arc::new(Mutex::new(DaemonState {
                settings,
                offers: Vec::new(),
            })),
            token,
            data_dir: data_dir.to_owned(),
        })
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
            ("GET", "/offers") => (200, json!(self.state.lock().unwrap().offers)),
            ("POST", "/offers") => self.post_offer(&req.body),
            ("GET", "/swaps") => (200, json!([])), // scaffold: engine wiring is the next M4a step
            // A bounded dynamic path. Kept strict so nothing is mistaken for a file to serve.
            ("GET", p) if p.starts_with("/swaps/") && valid_id(&p[7..]) => {
                (404, json!({"error": "no such swap"}))
            }
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
        let s = self.state.lock().unwrap();
        json!({
            "btc_node": reachable(&s.settings.btc_node),
            "xbtc_node": reachable(&s.settings.xbtc_node),
            "relays": s.settings.relays.len(),
            "tor": false, // scaffold: filled in once the relay connections are wired
            "active_swaps": 0,
        })
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

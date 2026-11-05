//! `sovereign-swap-relay`: a Nostr relay (NIP-01) hardened for carrying swap messages and nothing
//! else. It stores and forwards opaque events; it never sees identities or plaintext. Its job is to
//! survive abuse, so the controls are the point: only our event kind, a size cap, a per-connection
//! rate limit, a bounded store with a time-to-live, and a connection cap. See
//! `docs/design/0006-nostr-client-and-relay.md` and `docs/design/0003-adversarial-testing.md` (DoS).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hex::{Case, DisplayHex};
use bitcoin::secp256k1::{Secp256k1, Verification};
use serde_json::Value;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{accept_with_config, Error as WsProtoError, Message as WsMessage, WebSocket};

use crate::nostr::{Event, KIND_SWAP};

#[derive(Clone)]
pub struct RelayConfig {
    pub allowed_kinds: Vec<u32>,
    pub max_event_bytes: usize,
    pub max_connections: usize,
    /// Events a single connection may publish per minute before it is throttled.
    pub max_events_per_min: u32,
    /// Events older than this (by `created_at`) are not stored or served.
    pub retention_secs: u64,
    pub store_cap: usize,
}

impl Default for RelayConfig {
    fn default() -> RelayConfig {
        RelayConfig {
            allowed_kinds: vec![KIND_SWAP],
            max_event_bytes: 131_072,
            max_connections: 512,
            max_events_per_min: 240,
            retention_secs: 7 * 24 * 3600,
            store_cap: 100_000,
        }
    }
}

struct Store {
    events: VecDeque<Event>,
    cap: usize,
    retention: u64,
}

impl Store {
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn fresh(&self, e: &Event) -> bool {
        e.created_at + self.retention >= Store::now()
    }

    fn insert(&mut self, event: Event) -> bool {
        if self.events.iter().any(|e| e.id == event.id) {
            return false;
        }
        while self.events.len() >= self.cap {
            self.events.pop_front();
        }
        self.events.push_back(event);
        true
    }

    fn matching(&self, filter: &Filter) -> Vec<Event> {
        self.events
            .iter()
            .filter(|e| self.fresh(e) && filter.matches(e))
            .cloned()
            .collect()
    }
}

/// The subset of a NIP-01 REQ filter this relay honours: kinds and the `#p` recipient tag.
#[derive(Clone, Default)]
struct Filter {
    kinds: Option<Vec<u32>>,
    p_tags: Option<Vec<String>>,
}

impl Filter {
    fn parse(v: &Value) -> Filter {
        let kinds = v["kinds"].as_array().map(|a| {
            a.iter()
                .filter_map(|k| k.as_u64().map(|k| k as u32))
                .collect()
        });
        let p_tags = v["#p"].as_array().map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        });
        Filter { kinds, p_tags }
    }

    fn matches(&self, e: &Event) -> bool {
        if let Some(kinds) = &self.kinds {
            if !kinds.contains(&e.kind) {
                return false;
            }
        }
        if let Some(p) = &self.p_tags {
            let event_ps: Vec<&String> = e
                .tags
                .iter()
                .filter(|t| t.len() == 2 && t[0] == "p")
                .map(|t| &t[1])
                .collect();
            if !p.iter().any(|want| event_ps.contains(&want)) {
                return false;
            }
        }
        true
    }
}

type Outbox = Sender<String>;

struct Subscription {
    conn_id: u64,
    outbox: Outbox,
    sub_id: String,
    filter: Filter,
}

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(0);

pub struct RelayServer {
    cfg: RelayConfig,
    store: Arc<Mutex<Store>>,
    subs: Arc<Mutex<Vec<Subscription>>>,
    connections: Arc<AtomicUsize>,
}

impl RelayServer {
    pub fn new(cfg: RelayConfig) -> RelayServer {
        let store = Store {
            events: VecDeque::new(),
            cap: cfg.store_cap,
            retention: cfg.retention_secs,
        };
        RelayServer {
            cfg,
            store: Arc::new(Mutex::new(store)),
            subs: Arc::new(Mutex::new(Vec::new())),
            connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Binds and serves forever, a thread per connection. Returns the bound address.
    pub fn serve(self, bind: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind)?;
        self.accept_loop(listener);
        Ok(())
    }

    /// Binds to an ephemeral port and serves in a background thread; for tests and embedding.
    pub fn spawn(self, bind: &str) -> std::io::Result<String> {
        let listener = TcpListener::bind(bind)?;
        let addr = listener.local_addr()?;
        std::thread::spawn(move || self.accept_loop(listener));
        Ok(format!("ws://{addr}/"))
    }

    fn accept_loop(self, listener: TcpListener) {
        let server = Arc::new(self);
        for stream in listener.incoming().flatten() {
            if server.connections.load(Ordering::Relaxed) >= server.cfg.max_connections {
                continue; // drop the connection: we are at the cap
            }
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                server.connections.fetch_add(1, Ordering::Relaxed);
                server.serve_connection(stream);
                server.connections.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    fn serve_connection(&self, stream: TcpStream) {
        if stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .is_err()
        {
            return;
        }
        // A WebSocket client sends an Upgrade request; a browser sends a plain GET. Answer the
        // browser with a small informational page so the onion is not a blank screen, and let the
        // WebSocket handshake proceed untouched (peek leaves the request in the socket).
        match classify_request(&stream) {
            Some(RequestKind::WebSocket) => {}
            Some(RequestKind::Http) => {
                serve_landing(&stream);
                return;
            }
            None => return,
        }
        // Cap the frame size so an oversized event is refused at the protocol layer.
        let config =
            WebSocketConfig::default().max_message_size(Some(self.cfg.max_event_bytes + 4096));
        let mut ws = match accept_with_config(stream, Some(config)) {
            Ok(ws) => ws,
            Err(_) => return,
        };
        let (tx, rx): (Outbox, Receiver<String>) = mpsc::channel();
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let secp = Secp256k1::verification_only();
        let mut limiter = RateLimiter::new(self.cfg.max_events_per_min);

        loop {
            while let Ok(msg) = rx.try_recv() {
                if ws.send(WsMessage::Text(msg.into())).is_err() {
                    self.drop_subs(conn_id);
                    return;
                }
            }
            match ws.read() {
                Ok(WsMessage::Text(text)) => {
                    self.handle(&text, conn_id, &tx, &mut ws, &secp, &mut limiter)
                }
                Ok(WsMessage::Close(_)) => {
                    self.drop_subs(conn_id);
                    return;
                }
                Ok(_) => {}
                Err(
                    WsProtoError::Capacity(_) | WsProtoError::Protocol(_) | WsProtoError::Utf8(_),
                ) => {}
                Err(WsProtoError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => {
                    self.drop_subs(conn_id);
                    return;
                }
            }
        }
    }

    fn handle<S: Read + Write, C: Verification>(
        &self,
        text: &str,
        conn_id: u64,
        tx: &Outbox,
        ws: &mut WebSocket<S>,
        secp: &Secp256k1<C>,
        limiter: &mut RateLimiter,
    ) {
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return;
        };
        match v.get(0).and_then(Value::as_str) {
            Some("EVENT") => {
                let reply = self.accept_event(&v[1], secp, limiter);
                let _ = ws.send(WsMessage::Text(reply.into()));
            }
            Some("REQ") => {
                let sub_id = v.get(1).and_then(Value::as_str).unwrap_or("").to_owned();
                let filter = v.get(2).map(Filter::parse).unwrap_or_default();
                for event in self.store.lock().unwrap().matching(&filter) {
                    let _ = ws.send(WsMessage::Text(
                        format!(r#"["EVENT","{sub_id}",{}]"#, event.to_json()).into(),
                    ));
                }
                let _ = ws.send(WsMessage::Text(format!(r#"["EOSE","{sub_id}"]"#).into()));
                self.subs.lock().unwrap().push(Subscription {
                    conn_id,
                    outbox: tx.clone(),
                    sub_id,
                    filter,
                });
            }
            Some("CLOSE") => {
                let sub_id = v.get(1).and_then(Value::as_str).unwrap_or("");
                self.subs
                    .lock()
                    .unwrap()
                    .retain(|s| !(s.conn_id == conn_id && s.sub_id == sub_id));
            }
            _ => {}
        }
    }

    /// Applies every control, stores a good event and fans it out, and returns the NIP-01 OK line.
    fn accept_event<C: Verification>(
        &self,
        raw: &Value,
        secp: &Secp256k1<C>,
        limiter: &mut RateLimiter,
    ) -> String {
        let json = raw.to_string();
        let ok =
            |id: &str, accepted: bool, msg: &str| format!(r#"["OK","{id}",{accepted},"{msg}"]"#);
        let Ok(event) = Event::from_json(json.as_bytes()) else {
            return ok("", false, "invalid: unparseable event");
        };
        let id = event.id.to_hex_string(Case::Lower);
        if !limiter.allow() {
            return ok(&id, false, "rate-limited: too many events");
        }
        if json.len() > self.cfg.max_event_bytes {
            return ok(&id, false, "invalid: event too large");
        }
        if !self.cfg.allowed_kinds.contains(&event.kind) {
            return ok(&id, false, "blocked: kind not allowed");
        }
        if event.verify(secp).is_err() {
            return ok(&id, false, "invalid: bad id or signature");
        }
        if !self.store.lock().unwrap().fresh(&event) {
            return ok(&id, false, "invalid: outside retention window");
        }
        if !self.store.lock().unwrap().insert(event.clone()) {
            return ok(&id, true, "duplicate");
        }
        self.fan_out(&event);
        ok(&id, true, "")
    }

    fn fan_out(&self, event: &Event) {
        let line = format!(r#"["EVENT","{{}}",{}]"#, event.to_json());
        self.subs.lock().unwrap().retain(|sub| {
            if !sub.filter.matches(event) {
                return true;
            }
            let msg = line.replace("{}", &sub.sub_id);
            sub.outbox.send(msg).is_ok()
        });
    }

    fn drop_subs(&self, conn_id: u64) {
        self.subs.lock().unwrap().retain(|s| s.conn_id != conn_id);
    }
}

/// What the first bytes of a connection look like: a WebSocket upgrade, or a plain HTTP request.
enum RequestKind {
    WebSocket,
    Http,
}

/// Peeks at the request head (without consuming it, so the WebSocket handshake can still read it)
/// to tell a Nostr client's `Upgrade: websocket` from a browser's plain GET. Returns `None` if the
/// peer sends nothing, sends garbage, or stalls past a short deadline.
fn classify_request(stream: &TcpStream) -> Option<RequestKind> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buf = [0u8; 2048];
    loop {
        match stream.peek(&mut buf) {
            Ok(0) => return None,
            Ok(n) => {
                let head = &buf[..n];
                let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
                if contains(&lower, b"upgrade: websocket") || contains(&lower, b"upgrade:websocket")
                {
                    return Some(RequestKind::WebSocket);
                }
                // A complete header block with no upgrade line is a plain HTTP request.
                if contains(head, b"\r\n\r\n") {
                    return Some(RequestKind::Http);
                }
                // Headers still arriving (or the buffer is full without an upgrade): keep waiting
                // for the rest, up to the deadline.
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return None,
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Writes the informational landing page and closes. This is all a browser ever gets; the relay
/// itself speaks only WebSocket.
fn serve_landing(mut stream: &TcpStream) {
    let body = LANDING_HTML.as_bytes();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

/// The browser-facing page. Self-contained (no external assets), and deliberately plain: it states
/// what the relay is, that it is testing and holds no funds, and warns against sending coins.
const LANDING_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>sovereign-swap relay</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #0d1117; color: #c9d1d9;
         font: 16px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
  main { max-width: 42rem; margin: 0 auto; padding: 3rem 1.25rem 4rem; }
  h1 { font-size: 1.6rem; margin: 0 0 .25rem; color: #f0f6fc; }
  .sub { color: #8b949e; margin: 0 0 1.75rem; }
  .warn { border: 1px solid #9e6a03; background: #1c1708; border-radius: 8px;
          padding: 1rem 1.1rem; margin: 1.5rem 0; }
  .warn strong { color: #e3b341; }
  h2 { font-size: 1.05rem; margin: 1.75rem 0 .4rem; color: #f0f6fc; }
  code { background: #161b22; border: 1px solid #30363d; border-radius: 5px;
         padding: .1rem .35rem; font-size: .9em; }
  ul { padding-left: 1.2rem; } li { margin: .25rem 0; }
  footer { margin-top: 2.5rem; color: #6e7681; font-size: .85rem; }
  a { color: #58a6ff; }
</style>
</head>
<body>
<main>
  <h1>sovereign-swap relay</h1>
  <p class="sub">A hardened Nostr relay that carries swap messages between BTC and xBTC, and nothing else.</p>

  <div class="warn">
    <strong>Not live. Testing only.</strong>
    This is an experimental deployment. The relay holds no funds and no keys: it only stores and
    forwards opaque, end-to-end-encrypted messages. <strong>Do not send any coins to this service.</strong>
    It cannot receive them, and there is nothing here to pay.
  </div>

  <h2>What this is</h2>
  <p>sovereign-swap is a non-custodial, peer-to-peer atomic-swap protocol for Bitcoin (BTC) and
     Bitcoin Blake2b (xBTC). Parties swap directly on-chain via HTLCs; your keys and coins never
     leave your own machine. This relay is only the message layer: it speaks the Nostr protocol
     (NIP-01) over WebSocket and carries event kind <code>4859</code>.</p>

  <h2>How to connect</h2>
  <p>This address is a WebSocket endpoint, not a web page. Point a sovereign-swap client's relay
     list at it (for example <code>ws://&lt;this-onion&gt;:7777</code>) rather than opening it in a
     browser. The relay serves only kind 4859 and applies size, rate, and connection limits.</p>

  <h2>What the relay can and cannot see</h2>
  <ul>
    <li>It sees only throwaway routing keys and ciphertext.</li>
    <li>It never sees identities, swap details, or plaintext.</li>
    <li>It never holds, custodies, or moves funds.</li>
  </ul>

  <footer>
    TwentyOne.Life &middot; sovereign-swap &middot; AGPL-3.0 &middot; non-custodial, Tor-first.
    This chain shares Bitcoin's address format, but xBTC (Bitcoin Blake2b) is a different asset.
  </footer>
</main>
</body>
</html>
"#;

/// A sliding one-minute allowance, refilled continuously.
struct RateLimiter {
    per_min: u32,
    allowance: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(per_min: u32) -> RateLimiter {
        RateLimiter {
            per_min,
            allowance: per_min as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        self.allowance = (self.allowance
            + now.duration_since(self.last).as_secs_f64() * self.per_min as f64 / 60.0)
            .min(self.per_min as f64);
        self.last = now;
        if self.allowance >= 1.0 {
            self.allowance -= 1.0;
            true
        } else {
            false
        }
    }
}

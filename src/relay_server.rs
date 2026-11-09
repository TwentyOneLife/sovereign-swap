//! `sovereign-swap-relay`: a Nostr relay (NIP-01) hardened for carrying swap messages and nothing
//! else. It stores and forwards opaque events; it never sees identities or plaintext. Its job is to
//! survive abuse, so the controls are the point: only our event kind, a size cap, a per-connection
//! rate limit, a bounded store with a time-to-live, and a connection cap. See
//! `docs/design/0006-nostr-client-and-relay.md` and `docs/design/0003-adversarial-testing.md` (DoS).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
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
    /// Run the optional price proxy (#106): fetch the nonkyc BTCB2/BTC ticker over clearnet and serve
    /// it in the NIP-11 document for clients to read over Tor. Off by default; the operator opts in.
    pub price_proxy: bool,
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
            price_proxy: false,
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

/// Aggregate relay counters for operator visibility (design 0006 / #45), served in the NIP-11
/// document. Aggregate only, by deliberate design: never a pubkey, IP, or anything that identifies a
/// client or a swap. All monotonic since start except the live connection gauge (held separately).
#[derive(Default)]
struct Stats {
    started_at: u64,
    connections_total: AtomicU64,
    connections_rejected_at_cap: AtomicU64,
    events_accepted: AtomicU64,
    events_duplicate: AtomicU64,
    rejected_unparseable: AtomicU64,
    rejected_rate_limited: AtomicU64,
    rejected_too_large: AtomicU64,
    rejected_kind: AtomicU64,
    rejected_bad_sig: AtomicU64,
    rejected_stale: AtomicU64,
}

impl Stats {
    fn new() -> Stats {
        Stats {
            started_at: Store::now(),
            ..Default::default()
        }
    }
}

pub struct RelayServer {
    cfg: RelayConfig,
    store: Arc<Mutex<Store>>,
    subs: Arc<Mutex<Vec<Subscription>>>,
    connections: Arc<AtomicUsize>,
    stats: Arc<Stats>,
    /// The optional price-proxy cache (#106). `None` until the first successful fetch; served in the
    /// NIP-11 document only when `cfg.price_proxy` is set and the value is still fresh.
    price: crate::relay_price::PriceCache,
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
            stats: Arc::new(Stats::new()),
            price: Arc::new(Mutex::new(None)),
        }
    }

    /// The NIP-11 relay information document (design 0006 / #45), which doubles as the operator status
    /// read: static relay metadata plus the aggregate counters. Everything here is aggregate; nothing
    /// identifies a client or a swap.
    fn relay_info(&self) -> String {
        let s = &self.stats;
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut doc = serde_json::json!({
            "name": "sovereign-swap relay",
            "description": "A hardened Nostr relay that carries only sovereign-swap messages (kind 4859). Holds no funds.",
            "software": "https://github.com/TwentyOneLife/sovereign-swap",
            "version": env!("CARGO_PKG_VERSION"),
            "supported_nips": [1, 11],
            "limitation": {
                "max_message_length": self.cfg.max_event_bytes,
                "restricted_writes": true,
            },
            "swap_relay": {
                "allowed_kinds": self.cfg.allowed_kinds,
                "retention_secs": self.cfg.retention_secs,
                "max_connections": self.cfg.max_connections,
                "uptime_secs": Store::now().saturating_sub(s.started_at),
                "connections_now": self.connections.load(Ordering::Relaxed),
                "connections_total": n(&s.connections_total),
                "connections_rejected_at_cap": n(&s.connections_rejected_at_cap),
                "events_accepted": n(&s.events_accepted),
                "events_duplicate": n(&s.events_duplicate),
                "events_rejected": {
                    "unparseable": n(&s.rejected_unparseable),
                    "rate_limited": n(&s.rejected_rate_limited),
                    "too_large": n(&s.rejected_too_large),
                    "kind_not_allowed": n(&s.rejected_kind),
                    "bad_signature": n(&s.rejected_bad_sig),
                    "outside_retention": n(&s.rejected_stale),
                },
            },
        });
        // Price proxy (#106): include the cached price only when the proxy is enabled AND the value is
        // still fresh. A stale value (fetch failing for longer than MAX_AGE_SECS) is withheld so the
        // client never treats an old number as live. Nested under `swap_relay` so the top level stays
        // standard NIP-11. bid/ask are null when the ticker omitted them (never NaN in the JSON).
        if self.cfg.price_proxy {
            if let Some(p) = *self.price.lock().unwrap() {
                if Store::now().saturating_sub(p.as_of) < crate::relay_price::MAX_AGE_SECS {
                    let fin = |x: f64| {
                        if x.is_finite() {
                            serde_json::json!(x)
                        } else {
                            serde_json::Value::Null
                        }
                    };
                    doc["swap_relay"]["price"] = serde_json::json!({
                        "source": crate::relay_price::SOURCE,
                        "rate": p.rate,
                        "bid": fin(p.bid),
                        "ask": fin(p.ask),
                        "as_of": p.as_of,
                    });
                }
            }
        }
        doc.to_string()
    }

    /// Starts the optional price-proxy fetch loop when the operator enabled it. Done once at bring-up,
    /// before the accept loop takes `self`.
    fn start_price_proxy(&self) {
        if self.cfg.price_proxy {
            crate::relay_price::spawn(self.price.clone());
        }
    }

    /// Binds and serves forever, a thread per connection. Returns the bound address.
    pub fn serve(self, bind: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind)?;
        self.start_price_proxy();
        self.accept_loop(listener);
        Ok(())
    }

    /// Binds to an ephemeral port and serves in a background thread; for tests and embedding.
    pub fn spawn(self, bind: &str) -> std::io::Result<String> {
        let listener = TcpListener::bind(bind)?;
        let addr = listener.local_addr()?;
        self.start_price_proxy();
        std::thread::spawn(move || self.accept_loop(listener));
        Ok(format!("ws://{addr}/"))
    }

    fn accept_loop(self, listener: TcpListener) {
        let server = Arc::new(self);
        for stream in listener.incoming().flatten() {
            if server.connections.load(Ordering::Relaxed) >= server.cfg.max_connections {
                server
                    .stats
                    .connections_rejected_at_cap
                    .fetch_add(1, Ordering::Relaxed);
                continue; // drop the connection: we are at the cap
            }
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                server
                    .stats
                    .connections_total
                    .fetch_add(1, Ordering::Relaxed);
                server.connections.fetch_add(1, Ordering::Relaxed);
                server.serve_connection(stream);
                server.connections.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    fn serve_connection(&self, stream: TcpStream) {
        // The WebSocket handshake must be read with a generous timeout: this relay is Tor-first, and
        // a Tor circuit's round trip is well over the 50ms the read loop uses, so a short timeout set
        // before the handshake drops every Tor client (the handshake read times out and the accept
        // fails). Give the handshake room, then tighten to the short per-read timeout below for the
        // message loop.
        if stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .is_err()
        {
            return;
        }
        // A WebSocket client sends an Upgrade request; a browser sends a plain GET. Answer the
        // browser with a small informational page so the onion is not a blank screen, and let the
        // WebSocket handshake proceed untouched (peek leaves the request in the socket).
        match classify_request(&stream) {
            Some(RequestKind::WebSocket) => {}
            Some(RequestKind::Http { nip11: true }) => {
                serve_info(&stream, &self.relay_info());
                return;
            }
            Some(RequestKind::Http { nip11: false }) => {
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
        // Now the handshake is done, use a short read timeout so the message loop can interleave
        // reads with draining the outbound queue without blocking.
        if ws
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(50)))
            .is_err()
        {
            return;
        }
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
        let bump = |a: &AtomicU64| {
            a.fetch_add(1, Ordering::Relaxed);
        };
        let s = &self.stats;
        let Ok(event) = Event::from_json(json.as_bytes()) else {
            bump(&s.rejected_unparseable);
            return ok("", false, "invalid: unparseable event");
        };
        let id = event.id.to_hex_string(Case::Lower);
        if !limiter.allow() {
            bump(&s.rejected_rate_limited);
            return ok(&id, false, "rate-limited: too many events");
        }
        if json.len() > self.cfg.max_event_bytes {
            bump(&s.rejected_too_large);
            return ok(&id, false, "invalid: event too large");
        }
        if !self.cfg.allowed_kinds.contains(&event.kind) {
            bump(&s.rejected_kind);
            return ok(&id, false, "blocked: kind not allowed");
        }
        if event.verify(secp).is_err() {
            bump(&s.rejected_bad_sig);
            return ok(&id, false, "invalid: bad id or signature");
        }
        if !self.store.lock().unwrap().fresh(&event) {
            bump(&s.rejected_stale);
            return ok(&id, false, "invalid: outside retention window");
        }
        if !self.store.lock().unwrap().insert(event.clone()) {
            bump(&s.events_duplicate);
            return ok(&id, true, "duplicate");
        }
        bump(&s.events_accepted);
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
    /// A plain HTTP GET. `nip11` is set when it asked for `application/nostr+json`, the NIP-11 relay
    /// information document (which also carries the aggregate stats).
    Http {
        nip11: bool,
    },
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
                // A complete header block with no upgrade line is a plain HTTP request. A client
                // asking for `application/nostr+json` wants the NIP-11 document, not the landing page.
                if contains(head, b"\r\n\r\n") {
                    let nip11 = contains(&lower, b"application/nostr+json");
                    return Some(RequestKind::Http { nip11 });
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
fn serve_landing(stream: &TcpStream) {
    serve_http(
        stream,
        "Content-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n",
        LANDING_HTML.as_bytes(),
    );
}

/// Serves the NIP-11 relay information document (design 0006 / #45) to a plain GET that asked for
/// `application/nostr+json`. The permissive CORS header is standard for NIP-11 so a browser client can
/// read the relay's capabilities; the body is public, aggregate-only metadata.
fn serve_info(stream: &TcpStream, body: &str) {
    serve_http(
        stream,
        "Content-Type: application/nostr+json\r\nAccess-Control-Allow-Origin: *\r\n",
        body.as_bytes(),
    );
}

/// Writes one HTTP/1.1 response and closes cleanly. The request was only peeked, so its bytes are
/// still unread; closing a socket with unread data makes the kernel send RST, which discards any
/// unacknowledged response bytes and truncates the body over a high-latency path (whole on a LAN but
/// cut off over Tor). Half-close the write side to mark the end of the response, then drain the
/// request so the socket closes with a clean FIN.
fn serve_http(mut stream: &TcpStream, extra_headers: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 200 OK\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut sink = [0u8; 1024];
    while let Ok(n) = stream.read(&mut sink) {
        if n == 0 {
            break;
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn with_price(proxy: bool, as_of: u64) -> RelayServer {
        let server = RelayServer::new(RelayConfig {
            price_proxy: proxy,
            ..Default::default()
        });
        *server.price.lock().unwrap() = Some(crate::relay_price::CachedPrice {
            rate: 0.00385,
            bid: f64::NAN,
            ask: 0.00386,
            as_of,
        });
        server
    }

    #[test]
    fn nip11_price_is_served_only_when_enabled_and_fresh() {
        let now = Store::now();

        // Enabled + fresh: the price is present, with the rate and source, and a null bid (NaN -> null).
        let info: Value = serde_json::from_str(&with_price(true, now).relay_info()).unwrap();
        let price = &info["swap_relay"]["price"];
        assert!(price.is_object(), "fresh price should be served");
        assert_eq!(price["rate"], serde_json::json!(0.00385));
        assert_eq!(price["source"], "nonkyc BTCB2/BTC");
        assert_eq!(price["bid"], Value::Null);
        assert_eq!(price["ask"], serde_json::json!(0.00386));

        // Enabled but stale (older than MAX_AGE_SECS): withheld, so a dead fetch cannot look live.
        let stale = now.saturating_sub(crate::relay_price::MAX_AGE_SECS + 10);
        let info: Value = serde_json::from_str(&with_price(true, stale).relay_info()).unwrap();
        assert!(
            info["swap_relay"]["price"].is_null(),
            "stale price must be withheld"
        );

        // Disabled: even a fresh cached value is not served.
        let info: Value = serde_json::from_str(&with_price(false, now).relay_info()).unwrap();
        assert!(
            info["swap_relay"]["price"].is_null(),
            "disabled proxy serves no price"
        );
    }

    #[test]
    fn stats_count_rejections_and_surface_in_the_nip11_document() {
        let server = RelayServer::new(RelayConfig::default());
        let secp = Secp256k1::verification_only();
        let mut limiter = RateLimiter::new(1000);

        // An unparseable event is rejected and counted (no signing needed for this path).
        let reply = server.accept_event(&serde_json::json!({"nope": true}), &secp, &mut limiter);
        assert!(reply.contains(r#""OK""#) && reply.contains("false"));

        let info: Value = serde_json::from_str(&server.relay_info()).expect("valid NIP-11 JSON");
        assert_eq!(info["supported_nips"], serde_json::json!([1, 11]));
        assert_eq!(info["swap_relay"]["events_rejected"]["unparseable"], 1);
        assert_eq!(info["swap_relay"]["events_accepted"], 0);
        assert_eq!(
            info["swap_relay"]["allowed_kinds"],
            serde_json::json!([KIND_SWAP])
        );

        // Aggregate-only guarantee: the document must never carry a client identifier.
        let lower = server.relay_info().to_lowercase();
        for forbidden in ["pubkey", "\"ip\"", "client", "peer"] {
            assert!(!lower.contains(forbidden), "NIP-11 leaked {forbidden}");
        }
    }
}

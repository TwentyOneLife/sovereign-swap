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

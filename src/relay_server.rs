//! `sovereign-swap-relay`: a Nostr relay (NIP-01) hardened for carrying swap messages and nothing
//! else. It stores and forwards events. Directed (sealed) messages stay opaque: it never sees their
//! plaintext or the parties' identities. Broadcasts (offers and their withdrawals) are signed, not
//! encrypted, so they are public by nature; the relay reads a broadcast's payload only to retire a
//! withdrawn offer early (design 0021), never to learn anything secret. Its job is to survive abuse,
//! so the controls are the point: only our event kind, a size cap, a per-connection
//! rate limit on both publishes and subscriptions, a per-REQ result cap (bounding amplification), a
//! per-connection subscription cap, a bounded store with a time-to-live, and a connection cap. See
//! `docs/design/0006-nostr-client-and-relay.md` and `docs/design/0003-adversarial-testing.md` (DoS).

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hex::{Case, DisplayHex};
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use serde_json::Value;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{accept_with_config, Error as WsProtoError, Message as WsMessage, WebSocket};

use crate::envelope::{verify_broadcast, PublicIdentity, PUBLIC_IDENTITY_LEN};
use crate::nostr::{Event, KIND_SWAP};
use crate::swap::Message;

#[derive(Clone)]
pub struct RelayConfig {
    pub allowed_kinds: Vec<u32>,
    pub max_event_bytes: usize,
    pub max_connections: usize,
    /// Events a single connection may publish per minute before it is throttled.
    pub max_events_per_min: u32,
    /// REQ (subscription) messages a single connection may send per minute. A separate bucket from
    /// `max_events_per_min` so a publish flood cannot starve subscriptions, and the other way round.
    pub max_reqs_per_min: u32,
    /// The most events one REQ may stream back, regardless of (or capping) the client's `limit`. Bounds
    /// REQ amplification: one small REQ cannot pull the whole store.
    pub max_req_events: usize,
    /// The most live subscriptions one connection may hold. The honest client opens one; the cap stops a
    /// connection growing the subscription table without bound.
    pub max_subscriptions: usize,
    /// Seconds after the handshake a connection may go without sending a REQ before it is dropped. The
    /// honest client subscribes immediately, so this only reclaims sockets a squatter opened and left
    /// idle (connection-cap exhaustion).
    pub req_deadline_secs: u64,
    /// The most events that may queue for one subscriber before further fan-out to it is dropped. Bounds
    /// the memory a subscriber that stops reading can pin; a healthy client drains continuously.
    pub max_outbox_events: usize,
    /// Broadcast offers (events with no `p` tag): events older than this are not stored or served.
    pub retention_secs: u64,
    /// Broadcast offers: maximum event count.
    pub store_cap: usize,
    /// Broadcast offers: maximum total bytes (memory bound).
    pub max_store_bytes: usize,
    /// Directed messages (events with a `p` recipient tag) are held in a separate store with its own
    /// count, byte and retention budgets, so a flood of directed events cannot evict offers. Directed
    /// messages are also delivered to live subscribers by fan-out; the store copy only serves a
    /// recipient who reconnects within the swap window, so a shorter retention is enough.
    pub directed_store_cap: usize,
    pub directed_store_bytes: usize,
    pub directed_retention_secs: u64,
    /// Run the optional price proxy (#106): fetch the nonkyc BTCB2/BTC ticker over clearnet and serve
    /// it in the NIP-11 document for clients to read over Tor. Off by default; the operator opts in.
    pub price_proxy: bool,
    /// The most retired-offer tombstones kept at once (design 0021). Bounds the memory a stream of
    /// withdrawals can pin; oldest tombstones are evicted first. Sized to the offers store cap, since a
    /// tombstone exists to guard a stored offer. A tombstone is recorded only when a withdrawal really
    /// evicted an offer, so reaching this bound takes genuine offer-store traffic, not forged noise.
    pub max_tombstones: usize,
}

impl Default for RelayConfig {
    fn default() -> RelayConfig {
        RelayConfig {
            allowed_kinds: vec![KIND_SWAP],
            max_event_bytes: 131_072,
            max_connections: 512,
            max_events_per_min: 240,
            max_reqs_per_min: 120,
            max_req_events: 1_000,
            max_subscriptions: 64,
            req_deadline_secs: 30,
            max_outbox_events: 512,
            retention_secs: 7 * 24 * 3600,
            store_cap: 100_000,
            max_store_bytes: 64 * 1024 * 1024,
            directed_store_cap: 20_000,
            directed_store_bytes: 32 * 1024 * 1024,
            directed_retention_secs: 24 * 3600,
            price_proxy: false,
            max_tombstones: 100_000,
        }
    }
}

/// The on-the-wire size (bytes) an event occupies, used for the byte budget. The relay already bounds a
/// single event by `max_event_bytes` against this same JSON length, so the two budgets are in step.
fn event_size(e: &Event) -> usize {
    e.to_json().len()
}

/// An event is directed (addressed to one recipient) if it carries a `p` tag; otherwise it is a
/// broadcast offer. The two classes are stored separately with separate budgets, so a flood of one
/// class cannot evict the other.
fn is_directed(e: &Event) -> bool {
    e.tags.iter().any(|t| t.len() >= 2 && t[0] == "p")
}

struct Store {
    /// Each stored event, paired with its offer id when the event is a readable `Offer` broadcast
    /// (`None` for directed messages and unparseable broadcasts). The id is cached at insert so a
    /// withdrawal can evict matching offers by a cheap compare, never re-reading the envelope or
    /// running a signature verify under the store lock (design 0021).
    events: VecDeque<(Event, Option<[u8; 16]>)>,
    /// Event ids currently in `events`, kept in step with it, so dedupe is O(1) instead of a scan of the
    /// whole store under the lock on every accepted event.
    ids: HashSet<[u8; 32]>,
    /// Running sum of `event_size` over `events`, so the byte budget is enforced without a rescan.
    bytes: usize,
    cap: usize,
    /// Total bytes this store may hold. Bounds memory regardless of event count: a store full of
    /// maximum-size events would otherwise pin cap * max_event_bytes of RAM.
    max_bytes: usize,
    retention: u64,
}

impl Store {
    fn new(cap: usize, max_bytes: usize, retention: u64) -> Store {
        Store {
            events: VecDeque::new(),
            ids: HashSet::new(),
            bytes: 0,
            cap,
            max_bytes,
            retention,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// True if an event with this id is currently stored (and so was already verified when first
    /// accepted). Used for the replay fast-path in `accept_event`.
    fn contains_id(&self, id: &[u8; 32]) -> bool {
        self.ids.contains(id)
    }

    fn fresh(&self, e: &Event) -> bool {
        e.created_at + self.retention >= Store::now()
    }

    fn insert(&mut self, event: Event, offer_id: Option<[u8; 16]>) -> bool {
        if self.ids.contains(&event.id) {
            return false;
        }
        let sz = event_size(&event);
        // Evict oldest-first until BOTH the count cap and the byte budget admit the new event. The
        // non-empty guard stops an event larger than the whole budget from looping forever (it is still
        // bounded by `max_event_bytes`, which should be <= `max_bytes`).
        while self.events.len() >= self.cap
            || (self.bytes + sz > self.max_bytes && !self.events.is_empty())
        {
            if let Some((old, _)) = self.events.pop_front() {
                self.ids.remove(&old.id);
                self.bytes -= event_size(&old);
            } else {
                break;
            }
        }
        self.ids.insert(event.id);
        self.bytes += sz;
        self.events.push_back((event, offer_id));
        true
    }

    /// Remove every stored `Offer` with `offer_id` published under `author`'s routing key, keeping
    /// `ids` and `bytes` in step; returns how many were removed. Cheap by design: it compares the
    /// cached offer id and the event's routing key, never re-reading or re-verifying the envelope.
    fn evict_offer(&mut self, offer_id: [u8; 16], author: &XOnlyPublicKey) -> usize {
        let before = self.events.len();
        let mut kept = VecDeque::with_capacity(before);
        for (event, oid) in std::mem::take(&mut self.events) {
            if oid == Some(offer_id) && event.pubkey == *author {
                self.ids.remove(&event.id);
                self.bytes -= event_size(&event);
            } else {
                kept.push_back((event, oid));
            }
        }
        self.events = kept;
        before - self.events.len()
    }

    /// Fresh, matching events, newest first truncated to `max` (or the client's `limit` when smaller),
    /// then returned oldest-first. `max` bounds REQ amplification; `limit` honours the client's request.
    fn matching(&self, filter: &Filter, max: usize) -> Vec<Event> {
        let cap = filter.limit.map_or(max, |l| l.min(max));
        let mut hits: Vec<Event> = self
            .events
            .iter()
            .rev()
            .filter(|(e, _)| self.fresh(e) && filter.matches(e))
            .take(cap)
            .map(|(e, _)| e.clone())
            .collect();
        hits.reverse();
        hits
    }
}

/// A bounded set of retired `(offer_id, author routing key)` pairs (design 0021). A withdrawn offer is
/// remembered here so a later replay of the same offer is refused. Bounded like the stores: a count cap
/// and a retention equal to the offer retention (a tombstone older than the offer it guards is
/// pointless, since the offer would have aged out). Oldest-first eviction. The author key is part of
/// the key so one author can never tombstone another's offer id. Timestamps are relay-local, never the
/// author's clock.
/// A retired offer, keyed so one author can never tombstone another's offer id: the 16-byte offer id
/// and the author's serialized x-only routing key.
type TombKey = ([u8; 16], [u8; 32]);

struct Tombstones {
    /// Oldest first, so both expiry and the count cap evict from the front. Each entry is a key and the
    /// relay-local time it was recorded.
    entries: VecDeque<(TombKey, u64)>,
    live: HashSet<TombKey>,
    cap: usize,
    retention: u64,
}

impl Tombstones {
    fn new(cap: usize, retention: u64) -> Tombstones {
        Tombstones {
            entries: VecDeque::new(),
            live: HashSet::new(),
            cap,
            retention,
        }
    }

    fn key(offer_id: [u8; 16], author: &XOnlyPublicKey) -> TombKey {
        (offer_id, author.serialize())
    }

    /// Drop tombstones older than the retention from the front: once the offer one guards would itself
    /// have aged out of the store, the tombstone is pointless.
    fn prune(&mut self, now: u64) {
        while let Some(&(k, at)) = self.entries.front() {
            if at + self.retention < now {
                self.entries.pop_front();
                self.live.remove(&k);
            } else {
                break;
            }
        }
    }

    fn insert(&mut self, offer_id: [u8; 16], author: &XOnlyPublicKey, now: u64) {
        self.prune(now);
        let k = Self::key(offer_id, author);
        if self.live.contains(&k) {
            return;
        }
        while self.entries.len() >= self.cap {
            match self.entries.pop_front() {
                Some((old, _)) => {
                    self.live.remove(&old);
                }
                None => break,
            }
        }
        self.live.insert(k);
        self.entries.push_back((k, now));
    }

    /// Whether `(offer_id, author)` is tombstoned. Read-only, so it does not prune: an expired but not
    /// yet pruned tombstone keeps refusing the offer until the next insert prunes it, which only means a
    /// withdrawn offer stays refused a little longer, never the reverse.
    fn contains(&self, offer_id: [u8; 16], author: &XOnlyPublicKey) -> bool {
        self.live.contains(&Self::key(offer_id, author))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Read a broadcast event's payload. Broadcasts are signed, not encrypted (see `envelope.rs`), so the
/// relay can authenticate and read them with no key; this mirrors the client's decode in `routing.rs`.
/// Returns `None` for a sealed (directed) message, a malformed frame, a failed broadcast signature, or
/// a payload that is not a `Message`. The caller only parses broadcasts (events with no `p` tag).
fn broadcast_payload(event: &Event) -> Option<Message> {
    let frame = event.envelope().ok()?;
    if frame.len() < PUBLIC_IDENTITY_LEN {
        return None;
    }
    let (hint, env) = frame.split_at(PUBLIC_IDENTITY_LEN);
    let sender = PublicIdentity::from_bytes(hint).ok()?;
    let payload = verify_broadcast(&sender, env).ok()?;
    serde_json::from_slice::<Message>(&payload).ok()
}

/// The subset of a NIP-01 REQ filter this relay honours: kinds and the `#p` recipient tag.
#[derive(Clone, Default)]
struct Filter {
    kinds: Option<Vec<u32>>,
    p_tags: Option<Vec<String>>,
    limit: Option<usize>,
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
        let limit = v["limit"].as_u64().map(|l| l as usize);
        Filter {
            kinds,
            p_tags,
            limit,
        }
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

/// A bounded queue of outbound lines to one connection. Bounded (not `mpsc::channel`) so a subscriber
/// that stops reading cannot pin unbounded memory; `fan_out` uses `try_send` and drops a subscriber
/// whose queue is full rather than ever blocking under the subs lock.
type Outbox = SyncSender<String>;

struct Subscription {
    conn_id: u64,
    outbox: Outbox,
    sub_id: String,
    filter: Filter,
    /// Shared with the connection's serve loop. Set when fan-out drops this subscriber for a full queue,
    /// so the loop closes the connection: the client must reconnect (from its `since` watermark) rather
    /// than keep a live socket on which it silently never sees another event.
    evicted: Arc<AtomicBool>,
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
    /// Offers refused because their maker already withdrew them (design 0021 tombstone).
    rejected_withdrawn: AtomicU64,
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
    /// Broadcast offers (no `p` tag).
    offers: Arc<Mutex<Store>>,
    /// Directed messages (`p`-tagged). Separate budgets so a directed flood cannot evict offers.
    directed: Arc<Mutex<Store>>,
    /// Retired offers (design 0021): a withdrawn offer is remembered here so a replay is refused.
    tombstones: Arc<Mutex<Tombstones>>,
    subs: Arc<Mutex<Vec<Subscription>>>,
    connections: Arc<AtomicUsize>,
    stats: Arc<Stats>,
    /// The optional price-proxy cache (#106). `None` until the first successful fetch; served in the
    /// NIP-11 document only when `cfg.price_proxy` is set and the value is still fresh.
    price: crate::relay_price::PriceCache,
}

impl RelayServer {
    pub fn new(cfg: RelayConfig) -> RelayServer {
        let offers = Store::new(cfg.store_cap, cfg.max_store_bytes, cfg.retention_secs);
        let directed = Store::new(
            cfg.directed_store_cap,
            cfg.directed_store_bytes,
            cfg.directed_retention_secs,
        );
        // A tombstone guards a stored offer, so it shares the offers' retention window.
        let tombstones = Tombstones::new(cfg.max_tombstones, cfg.retention_secs);
        RelayServer {
            cfg,
            offers: Arc::new(Mutex::new(offers)),
            directed: Arc::new(Mutex::new(directed)),
            tombstones: Arc::new(Mutex::new(tombstones)),
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
                "max_subscriptions": self.cfg.max_subscriptions,
                "max_limit": self.cfg.max_req_events,
                "restricted_writes": true,
            },
            "swap_relay": {
                "allowed_kinds": self.cfg.allowed_kinds,
                "retention_secs": self.cfg.retention_secs,
                "offers_store_cap": self.cfg.store_cap,
                "offers_store_bytes": self.cfg.max_store_bytes,
                "directed_store_cap": self.cfg.directed_store_cap,
                "directed_store_bytes": self.cfg.directed_store_bytes,
                "directed_retention_secs": self.cfg.directed_retention_secs,
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
                    "withdrawn": n(&s.rejected_withdrawn),
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
            // Reserve the slot before spawning so a burst of accepts cannot overshoot the cap (the old
            // load-then-increment-in-thread order raced). Roll back and drop if we were already full.
            if server.connections.fetch_add(1, Ordering::SeqCst) >= server.cfg.max_connections {
                server.connections.fetch_sub(1, Ordering::SeqCst);
                server
                    .stats
                    .connections_rejected_at_cap
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            server
                .stats
                .connections_total
                .fetch_add(1, Ordering::Relaxed);
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                server.serve_connection(stream);
                server.connections.fetch_sub(1, Ordering::SeqCst);
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
        // At least 1, so a misconfigured `max_outbox_events: 0` is not a rendezvous channel that would
        // drop every subscriber on its first event.
        let (tx, rx): (Outbox, Receiver<String>) =
            mpsc::sync_channel(self.cfg.max_outbox_events.max(1));
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        let evicted = Arc::new(AtomicBool::new(false));
        let secp = Secp256k1::verification_only();
        let mut event_limiter = RateLimiter::new(self.cfg.max_events_per_min);
        let mut req_limiter = RateLimiter::new(self.cfg.max_reqs_per_min);
        let mut seen_req = false;
        let opened = Instant::now();
        let req_deadline = Duration::from_secs(self.cfg.req_deadline_secs);

        loop {
            // A subscriber whose outbox overflowed is closed here so the client reconnects from its
            // watermark rather than staying connected but deaf.
            if evicted.load(Ordering::Relaxed) {
                self.drop_subs(conn_id);
                return;
            }
            // Reclaim a socket that never subscribed: an honest client sends its REQ immediately, so a
            // connection still silent past the deadline is a squatter holding a connection slot.
            if !seen_req && opened.elapsed() > req_deadline {
                self.drop_subs(conn_id);
                return;
            }
            while let Ok(msg) = rx.try_recv() {
                if ws.send(WsMessage::Text(msg.into())).is_err() {
                    self.drop_subs(conn_id);
                    return;
                }
            }
            match ws.read() {
                Ok(WsMessage::Text(text)) => self.handle(
                    &text,
                    conn_id,
                    &tx,
                    &mut ws,
                    &secp,
                    &mut event_limiter,
                    &mut req_limiter,
                    &mut seen_req,
                    &evicted,
                ),
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

    #[allow(clippy::too_many_arguments)]
    fn handle<S: Read + Write, C: Verification>(
        &self,
        text: &str,
        conn_id: u64,
        tx: &Outbox,
        ws: &mut WebSocket<S>,
        secp: &Secp256k1<C>,
        event_limiter: &mut RateLimiter,
        req_limiter: &mut RateLimiter,
        seen_req: &mut bool,
        evicted: &Arc<AtomicBool>,
    ) {
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return;
        };
        match v.get(0).and_then(Value::as_str) {
            Some("EVENT") => {
                let reply = self.accept_event(&v[1], secp, event_limiter);
                let _ = ws.send(WsMessage::Text(reply.into()));
            }
            Some("REQ") => {
                // A REQ, even one later throttled, marks the connection as a real subscriber so the
                // idle-socket deadline no longer applies to it.
                *seen_req = true;
                // REQ has its own rate bucket (a store scan is costlier than accepting an event) and a
                // per-connection subscription cap. Over-budget REQs are dropped silently: the client
                // ignores CLOSED/NOTICE, and its single honest REQ is always within budget.
                if !req_limiter.allow() {
                    return;
                }
                if self
                    .subs
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|s| s.conn_id == conn_id)
                    .count()
                    >= self.cfg.max_subscriptions
                {
                    return;
                }
                let sub_id = v.get(1).and_then(Value::as_str).unwrap_or("").to_owned();
                let filter = v.get(2).map(Filter::parse).unwrap_or_default();
                // Collect under each lock, release BEFORE sending: a `for` over the locked expression
                // would hold the store guard across every network write, so one non-reading REQ client
                // (a stalled `ws.send`) would freeze publishing relay-wide. Query both class stores and
                // merge: each store is capped at `max_req_events` (so clones stay bounded at 2x that),
                // then we keep the newest `effective` across both to honour the client's `limit`.
                let max = self.cfg.max_req_events;
                let mut hits = self.offers.lock().unwrap().matching(&filter, max);
                hits.extend(self.directed.lock().unwrap().matching(&filter, max));
                hits.sort_by_key(|e| e.created_at);
                let effective = filter.limit.map_or(max, |l| l.min(max));
                if hits.len() > effective {
                    hits = hits.split_off(hits.len() - effective);
                }
                for event in hits {
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
                    evicted: evicted.clone(),
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
        // Route by class first (cheap: a tag scan, no crypto): offers and directed messages have
        // separate stores and budgets.
        let directed = is_directed(&event);
        let store = if directed {
            &self.directed
        } else {
            &self.offers
        };
        // Replay fast-path (DoS, design 0003/0020): an event already in the store was fully verified
        // when first accepted, and an event id is the hash of its content, so a matching id can only
        // be the same event. Reject the replay as a duplicate BEFORE the Schnorr and ML-DSA verifies,
        // so a flood of a captured valid event cannot force two signature verifies per copy. A
        // withdrawn offer is evicted from the store (its id removed), so its replay still falls
        // through to the tombstone check below rather than being waved through here.
        if store.lock().unwrap().contains_id(&event.id) {
            bump(&s.events_duplicate);
            return ok(&id, true, "duplicate");
        }
        if event.verify(secp).is_err() {
            bump(&s.rejected_bad_sig);
            return ok(&id, false, "invalid: bad id or signature");
        }
        if !store.lock().unwrap().fresh(&event) {
            bump(&s.rejected_stale);
            return ok(&id, false, "invalid: outside retention window");
        }
        // Design 0021: a broadcast is signed, not encrypted, so the relay can read it (after the
        // freshness check, so a stale event has no side effect). An `Offer` whose maker already
        // withdrew it is refused; a `Withdraw` retires its author's offer early. Everything else,
        // including a broadcast that does not parse, is stored and served exactly as before. The
        // cached offer id rides into the store so a later withdrawal evicts by a cheap compare.
        let mut offer_id = None;
        if !directed {
            match broadcast_payload(&event) {
                Some(Message::Offer(offer)) => {
                    if self
                        .tombstones
                        .lock()
                        .unwrap()
                        .contains(offer.id, &event.pubkey)
                    {
                        bump(&s.rejected_withdrawn);
                        return ok(&id, false, "blocked: offer withdrawn");
                    }
                    offer_id = Some(offer.id);
                }
                Some(Message::Withdraw { offer_id: target }) => {
                    self.retire_offer(target, &event.pubkey);
                }
                _ => {}
            }
        }
        if !store.lock().unwrap().insert(event.clone(), offer_id) {
            bump(&s.events_duplicate);
            return ok(&id, true, "duplicate");
        }
        bump(&s.events_accepted);
        self.fan_out(&event);
        ok(&id, true, "")
    }

    /// Design 0021: retire `author`'s offer early on an authentic withdrawal. Evict every stored
    /// `Offer` with this id published under the same routing key (the author check, mirroring the
    /// client's own rule in `routing.rs`, stops a third party retiring someone else's offer), and,
    /// only if something was actually evicted, remember the pair so a later replay of that offer is
    /// refused. Recording a tombstone only on a real eviction means a flood of forged withdrawals
    /// cannot push out genuine tombstones: a flooder must first pay the already-bounded offers-store
    /// budget (design 0020). The offers lock is taken and released before the tombstones lock, never
    /// both at once. The withdrawal event itself is still stored and fanned out by the caller.
    fn retire_offer(&self, offer_id: [u8; 16], author: &XOnlyPublicKey) {
        let evicted = self.offers.lock().unwrap().evict_offer(offer_id, author);
        if evicted > 0 {
            self.tombstones
                .lock()
                .unwrap()
                .insert(offer_id, author, Store::now());
        }
    }

    fn fan_out(&self, event: &Event) {
        let line = format!(r#"["EVENT","{{}}",{}]"#, event.to_json());
        self.subs.lock().unwrap().retain(|sub| {
            if !sub.filter.matches(event) {
                return true;
            }
            let msg = line.replace("{}", &sub.sub_id);
            // try_send, never a blocking send: we hold the subs lock, so a slow subscriber must not be
            // able to stall fan-out to everyone else. A full (or gone) queue drops this subscriber and
            // flags its connection to close, so the client reconnects instead of going silently deaf.
            if sub.outbox.try_send(msg).is_ok() {
                true
            } else {
                sub.evicted.store(true, Ordering::Relaxed);
                false
            }
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

/// A fresh connection starts with this many tokens, not a full per-minute bucket. Because the relay is
/// Tor-first it has no per-source identity, so a full starting bucket would let an attacker reset its
/// whole allowance just by reconnecting; a small burst keeps a cold connection cheap.
const RATE_BURST: f64 = 10.0;

impl RateLimiter {
    fn new(per_min: u32) -> RateLimiter {
        RateLimiter {
            per_min,
            allowance: RATE_BURST.min(per_min as f64),
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
    use bitcoin::secp256k1::Keypair;

    /// An x-only key to stand in for an offer author's routing key in the tombstone unit tests.
    fn author(seed: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[seed; 32])
            .unwrap()
            .x_only_public_key()
            .0
    }

    #[test]
    fn a_tombstone_expires_after_its_retention() {
        let a = author(5);
        let mut tomb = Tombstones::new(10, 100);
        tomb.insert([1; 16], &a, 1_000);
        assert!(tomb.contains([1; 16], &a));
        assert_eq!(tomb.len(), 1);

        // An insert past the retention prunes the stale tombstone (relay-local time, not the author's).
        tomb.insert([2; 16], &a, 1_000 + 100 + 1);
        assert!(
            !tomb.contains([1; 16], &a),
            "a tombstone older than the retention must be pruned"
        );
        assert!(tomb.contains([2; 16], &a));
        assert_eq!(tomb.len(), 1);
    }

    #[test]
    fn a_tombstone_is_keyed_by_author_so_one_author_cannot_block_anothers_id() {
        let (a, b) = (author(5), author(6));
        let mut tomb = Tombstones::new(10, 100);
        tomb.insert([1; 16], &a, 1_000);
        assert!(tomb.contains([1; 16], &a));
        assert!(
            !tomb.contains([1; 16], &b),
            "a tombstone for one author must not match the same id under another author"
        );
    }

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

    #[test]
    fn a_replay_is_dropped_as_duplicate_before_the_signature_verify() {
        use crate::nostr::Event;
        // DoS (design 0003/0020): a replay of a stored event must be rejected as a duplicate before
        // the Schnorr and ML-DSA verifies run, so a flood of a captured valid event cannot force a
        // verify per copy. We prove the dedup runs first by replaying with a CORRUPTED signature but
        // the same id: the old order (verify first) answers "bad id or signature"; the fast-path
        // answers "duplicate".
        let server = RelayServer::new(RelayConfig::default());
        let secp = Secp256k1::new();
        let kp = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[9u8; 32]).unwrap();
        let ev = Event::build(&secp, &kp, Event::now_for_test(), vec![], &[1, 2, 3]);
        let mut limiter = RateLimiter::new(1000);

        let good: Value = serde_json::from_str(&ev.to_json()).unwrap();
        let r1 = server.accept_event(&good, &secp, &mut limiter);
        assert!(r1.contains("true"), "first copy should be accepted: {r1}");
        assert!(
            !r1.contains("duplicate"),
            "first copy is not a duplicate: {r1}"
        );

        // Same id (content unchanged, so id is unchanged), but flip one hex digit of the signature.
        let mut bad = good.clone();
        let sig = bad["sig"].as_str().unwrap().to_owned();
        let last = sig.chars().last().unwrap();
        let swapped = if last == '0' { '1' } else { '0' };
        bad["sig"] = Value::String(format!("{}{}", &sig[..sig.len() - 1], swapped));

        let r2 = server.accept_event(&bad, &secp, &mut limiter);
        assert!(
            r2.contains("duplicate"),
            "a replay (even with a broken sig) must be dropped as a duplicate before the verify: {r2}"
        );
        assert!(
            !r2.contains("bad id or signature"),
            "the dedup fast-path must run before the signature verify: {r2}"
        );
    }

    #[test]
    fn a_subscriber_with_a_full_outbox_is_dropped_not_blocked() {
        use crate::nostr::Event;
        let server = RelayServer::new(RelayConfig::default());
        let secp = Secp256k1::new();
        let kp = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[7u8; 32]).unwrap();
        let ev = Event::build(&secp, &kp, Event::now_for_test(), vec![], &[1, 2, 3]);

        // A subscriber whose bounded queue (capacity 1) is already full: the next fan-out must not block.
        let (tx, _rx) = mpsc::sync_channel::<String>(1);
        tx.try_send("prefill".to_owned()).unwrap();
        let evicted = Arc::new(AtomicBool::new(false));
        server.subs.lock().unwrap().push(Subscription {
            conn_id: 1,
            outbox: tx,
            sub_id: "s".to_owned(),
            filter: Filter::default(),
            evicted: evicted.clone(),
        });

        server.fan_out(&ev);

        assert!(
            server.subs.lock().unwrap().is_empty(),
            "a subscriber whose outbox is full must be dropped, never block fan-out under the lock"
        );
        assert!(
            evicted.load(Ordering::Relaxed),
            "a dropped-for-full subscriber must be flagged so its connection is closed"
        );
    }
}

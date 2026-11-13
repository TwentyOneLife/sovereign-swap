//! A `RelayConn` over a real Nostr relay via WebSocket (NIP-01), Tor-first.
//!
//! The socket is reached directly or, by default, through a Tor SOCKS5 proxy so a relay's `.onion`
//! is dialed inside the Tor circuit; content is end-to-end encrypted by the envelope regardless, so
//! no TLS is used on the Tor path. One owner thread holds the WebSocket: it sends what `publish`
//! queues and buffers the events a `REQ` subscription returns. See design 0006.

use std::collections::VecDeque;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::XOnlyPublicKey;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{client::client_with_config, Error as WsProtoError, Message as WsMessage};

use crate::nostr::{Event, KIND_SWAP};
use crate::routing::{RelayConn, RelayStatus};

/// Caps on untrusted input from a relay: a message larger than this is refused, and no more than
/// this many events are buffered (oldest dropped), so a hostile or flooding relay cannot exhaust
/// memory. Our events are a few KiB; a relay's max event is 128 KiB.
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_BUFFERED_EVENTS: usize = 10_000;
const MAX_BUFFERED_REJECTIONS: usize = 1_000;
/// How many stored events a (re)subscription accepts, so a reconnect does not pull the relay's whole
/// retention window again; how often to ping so a half-open socket is noticed and reconnected rather
/// than silently swallowing published offers; and the cap on reconnect backoff.
const SUB_LIMIT: u32 = 500;
const PING_INTERVAL: Duration = Duration::from_secs(20);
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct WsConn {
    outgoing: Sender<String>,
    incoming: Arc<Mutex<VecDeque<Event>>>,
    /// Relay `OK:false` replies to our publishes (NIP-01), so a rejected publish is observable rather
    /// than silently dropped (#151). Bounded; drained by `take_rejections`.
    rejections: Arc<Mutex<VecDeque<String>>>,
    shutdown: Arc<AtomicBool>,
    /// The relay URL and whether the worker currently holds a live socket, for the connected-relays
    /// display (design 0029). `live` is set while the worker is serving and cleared when the socket
    /// breaks or during reconnect backoff.
    url: String,
    live: Arc<AtomicBool>,
    _worker: std::thread::JoinHandle<()>,
}

impl Drop for WsConn {
    fn drop(&mut self) {
        // Tell the worker to stop reconnecting and exit; its socket closes with it.
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub enum WsError {
    Io(std::io::Error),
    Socks(String),
    Handshake(String),
    Url(String),
}

impl WsConn {
    /// Connects to `url` (ws://host:port/...). With `socks`, dials through that Tor SOCKS5 proxy so
    /// an `.onion` host resolves inside Tor; without it, a direct TCP connection.
    pub fn connect(url: &str, socks: Option<&str>) -> WsConn {
        // Attempt the first dial synchronously, so a reachable relay is live the instant this returns.
        // But a failure is NOT fatal (#113): a transient Tor-SOCKS race at boot, or a briefly-down
        // relay, would otherwise stop the engine from starting at all, leaving a node unable to drive
        // its own in-flight swaps. Instead the worker connects (and later reconnects) asynchronously
        // with backoff, so the engine always comes up and discovery catches up when the relay is ready.
        let initial = dial(url, socks)
            .and_then(|mut s| subscribe(&mut s, None).map(|()| s))
            .ok();
        let incoming: Arc<Mutex<VecDeque<Event>>> = Arc::default();
        let buffer = Arc::clone(&incoming);
        let rejections: Arc<Mutex<VecDeque<String>>> = Arc::default();
        let worker_rejections = Arc::clone(&rejections);
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        // Connected the instant the first dial succeeded; the worker keeps it current thereafter.
        let live = Arc::new(AtomicBool::new(initial.is_some()));
        let worker_live = Arc::clone(&live);
        let worker_url = url.to_owned();
        let socks = socks.map(str::to_owned);
        let worker = std::thread::spawn(move || {
            run(
                &worker_url,
                socks.as_deref(),
                rx,
                buffer,
                worker_rejections,
                &worker_shutdown,
                &worker_live,
                initial,
            );
        });
        WsConn {
            outgoing: tx,
            incoming,
            rejections,
            shutdown,
            url: url.to_owned(),
            live,
            _worker: worker,
        }
    }

    /// The relay rejections (NIP-01 `OK:false`) seen since the last call, drained. A rejected publish
    /// is recorded here instead of being silently swallowed (#151), so a caller can surface it or act
    /// on it (for example re-grind to a relay's proof-of-work floor, design 0020).
    pub fn take_rejections(&self) -> Vec<String> {
        self.rejections.lock().unwrap().drain(..).collect()
    }
}

/// Dials `url` (direct or through the Tor SOCKS proxy), does the WebSocket handshake, and leaves the
/// socket in short-timeout non-blocking mode for the worker loop.
fn dial(url: &str, socks: Option<&str>) -> Result<tungstenite::WebSocket<TcpStream>, WsError> {
    let (host, port, _path) = parse_ws_url(url)?;
    let stream = match socks {
        Some(proxy) => crate::socks::socks5_connect(proxy, &host, port, Duration::from_secs(30))
            .map_err(|e| WsError::Socks(e.to_string()))?,
        None => TcpStream::connect((host.as_str(), port)).map_err(WsError::Io)?,
    };
    // A generous timeout for the handshake: over a Tor onion the server's upgrade response can take
    // several seconds, far longer than the 100 ms the worker loop wants. The short timeout is set
    // below, once the handshake is done and the worker needs non-blocking polling.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(WsError::Io)?;
    // Bound total message size (memory) but leave the frame size at the library default: a too-small
    // frame cap makes tungstenite assert rather than error on an oversized frame.
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_BYTES));
    let (socket, _resp) = client_with_config(url, stream, Some(config))
        .map_err(|e| WsError::Handshake(e.to_string()))?;
    socket
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(WsError::Io)?;
    Ok(socket)
}

/// Subscribes to our event kind, bounded by `SUB_LIMIT`; `since` (a watermark of the newest event
/// already seen) keeps a reconnect from replaying the whole retention window. We filter and route
/// client-side regardless.
fn subscribe(
    socket: &mut tungstenite::WebSocket<TcpStream>,
    since: Option<u64>,
) -> Result<(), WsError> {
    let filter = match since {
        Some(s) => format!(r#"{{"kinds":[{KIND_SWAP}],"since":{s},"limit":{SUB_LIMIT}}}"#),
        None => format!(r#"{{"kinds":[{KIND_SWAP}],"limit":{SUB_LIMIT}}}"#),
    };
    socket
        .send(WsMessage::Text(format!(r#"["REQ","s",{filter}]"#).into()))
        .map_err(|e| WsError::Handshake(e.to_string()))
}

/// Connects (or reconnects) with capped backoff, resubscribing from the watermark `since` so a
/// reconnect does not replay the whole retention window. Returns `None` only if a shutdown is
/// requested while it is still trying, so the caller stops cleanly. Used both for the initial connect
/// when the first dial failed (#113) and for healing a dropped socket.
fn connect_with_backoff(
    url: &str,
    socks: Option<&str>,
    since: Option<u64>,
    shutdown: &AtomicBool,
) -> Option<tungstenite::WebSocket<TcpStream>> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return None;
        }
        match dial(url, socks).and_then(|mut s| subscribe(&mut s, since).map(|()| s)) {
            Ok(s) => return Some(s),
            Err(_) => {
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
            }
        }
    }
}

/// The owner thread: connect if needed, serve the socket until it breaks, then reconnect (unless
/// shutting down). `initial` is the socket from the synchronous first dial, or `None` when that dial
/// failed and the first connection must be made here (#113).
// The worker's inputs are all distinct channels/flags it needs; grouping them into a struct would not
// make it clearer.
#[allow(clippy::too_many_arguments)]
fn run(
    url: &str,
    socks: Option<&str>,
    rx: Receiver<String>,
    buffer: Arc<Mutex<VecDeque<Event>>>,
    rejections: Arc<Mutex<VecDeque<String>>>,
    shutdown: &AtomicBool,
    live: &AtomicBool,
    initial: Option<tungstenite::WebSocket<TcpStream>>,
) {
    let mut since: Option<u64> = None;
    let mut next = initial;
    loop {
        let mut socket = match next.take() {
            Some(s) => s,
            None => {
                live.store(false, Ordering::Relaxed); // disconnected while backing off
                match connect_with_backoff(url, socks, since, shutdown) {
                    Some(s) => s,
                    None => return, // shutting down
                }
            }
        };
        live.store(true, Ordering::Relaxed); // a live socket, serving
        serve(&mut socket, &rx, &buffer, &rejections, shutdown, &mut since);
        live.store(false, Ordering::Relaxed); // the socket broke
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        // The socket broke; the next iteration reconnects from the watermark.
    }
}

/// One connection's lifetime: drain the outgoing queue, ping periodically so a half-open socket is
/// noticed, and buffer incoming events (tracking the newest `created_at` as the reconnect watermark).
/// Returns when the socket breaks or a shutdown is requested.
fn serve(
    socket: &mut tungstenite::WebSocket<TcpStream>,
    rx: &Receiver<String>,
    buffer: &Arc<Mutex<VecDeque<Event>>>,
    rejections: &Arc<Mutex<VecDeque<String>>>,
    shutdown: &AtomicBool,
    since: &mut Option<u64>,
) {
    let mut last_ping = Instant::now();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        loop {
            match rx.try_recv() {
                Ok(text) => {
                    if socket.send(WsMessage::Text(text.into())).is_err() {
                        return;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }
        if last_ping.elapsed() >= PING_INTERVAL {
            if socket.send(WsMessage::Ping(Vec::new().into())).is_err() {
                return;
            }
            last_ping = Instant::now();
        }
        match socket.read() {
            Ok(WsMessage::Text(text)) => {
                if let Some(event) = parse_event_message(&text) {
                    *since = Some(since.map_or(event.created_at, |s| s.max(event.created_at)));
                    let mut buf = buffer.lock().unwrap();
                    if buf.len() >= MAX_BUFFERED_EVENTS {
                        buf.pop_front();
                    }
                    buf.push_back(event);
                } else if let Some((id, false, msg)) = parse_ok(&text) {
                    // The relay refused this publish (NIP-01 OK:false). Record it so it is not silently
                    // dropped (#151) and log it; the owner thread keeps serving.
                    eprintln!("relay rejected event {id}: {msg}");
                    let mut rej = rejections.lock().unwrap();
                    if rej.len() >= MAX_BUFFERED_REJECTIONS {
                        rej.pop_front();
                    }
                    rej.push_back(format!("{id}: {msg}"));
                }
            }
            Ok(WsMessage::Close(_)) => return,
            Ok(_) => {}
            // A hostile relay sending an oversized, malformed or non-UTF-8 frame must not drop the
            // connection: skip that frame and keep reading. Only a closed or broken socket ends it.
            Err(WsProtoError::Capacity(_) | WsProtoError::Protocol(_) | WsProtoError::Utf8(_)) => {}
            Err(WsProtoError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return,
        }
    }
}

/// Parses a relay `["OK", <event-id>, <accepted>, <message>]` reply (NIP-01); `None` for any other
/// line. Used to notice a rejected publish instead of ignoring it.
fn parse_ok(text: &str) -> Option<(String, bool, String)> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let arr = v.as_array()?;
    if arr.first()?.as_str()? != "OK" {
        return None;
    }
    let id = arr.get(1)?.as_str()?.to_owned();
    let accepted = arr.get(2)?.as_bool()?;
    let msg = arr.get(3).and_then(|m| m.as_str()).unwrap_or("").to_owned();
    Some((id, accepted, msg))
}

/// Reads a relay's `["EVENT","s",{...}]` line into an Event; ignores EOSE, OK, NOTICE, CLOSED.
fn parse_event_message(text: &str) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let arr = v.as_array()?;
    if arr.first()?.as_str()? != "EVENT" {
        return None;
    }
    Event::from_json(arr.get(2)?.to_string().as_bytes()).ok()
}

impl RelayConn for WsConn {
    fn publish(&self, event: Event) {
        let _ = self
            .outgoing
            .send(format!(r#"["EVENT",{}]"#, event.to_json()));
    }

    fn poll(&self, subscriber: &XOnlyPublicKey) -> Vec<Event> {
        let drained: Vec<Event> = self.incoming.lock().unwrap().drain(..).collect();
        drained
            .into_iter()
            .filter(|e| e.pubkey != *subscriber)
            .filter(|e| e.recipient().is_none_or(|to| to == *subscriber))
            .collect()
    }

    fn status(&self) -> Vec<RelayStatus> {
        vec![RelayStatus {
            url: self.url.clone(),
            connected: self.live.load(Ordering::Relaxed),
        }]
    }
}

fn parse_ws_url(url: &str) -> Result<(String, u16, String), WsError> {
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| WsError::Url("only ws:// is supported".into()))?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| WsError::Url("host:port required".into()))?;
    let port = port.parse().map_err(|_| WsError::Url("bad port".into()))?;
    Ok((host.to_owned(), port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ws_urls() {
        assert_eq!(
            parse_ws_url("ws://relay.example:7777/").unwrap(),
            ("relay.example".into(), 7777, "/".into())
        );
        assert_eq!(parse_ws_url("ws://abc.onion:80").unwrap().1, 80);
        assert!(parse_ws_url("wss://x:1").is_err());
    }

    // #113: connecting to an unreachable relay must NOT fail or block. The first dial fails fast
    // (connection refused), the worker reconnects in the background, and the engine can still start.
    // Port 1 is privileged/unused, so the dial is refused immediately; dropping the conn stops the
    // worker (shutdown on drop).
    #[test]
    fn connect_to_an_unreachable_relay_returns_a_pending_connection() {
        let conn = WsConn::connect("ws://127.0.0.1:1/", None);
        // It exists and did not panic; nothing has been received over the (never-established) socket.
        assert!(conn.incoming.lock().unwrap().is_empty());
        drop(conn); // sets shutdown; the reconnect loop exits at its next check
    }
}

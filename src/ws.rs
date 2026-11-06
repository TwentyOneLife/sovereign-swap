//! A `RelayConn` over a real Nostr relay via WebSocket (NIP-01), Tor-first.
//!
//! The socket is reached directly or, by default, through a Tor SOCKS5 proxy so a relay's `.onion`
//! is dialed inside the Tor circuit; content is end-to-end encrypted by the envelope regardless, so
//! no TLS is used on the Tor path. One owner thread holds the WebSocket: it sends what `publish`
//! queues and buffers the events a `REQ` subscription returns. See design 0006.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use bitcoin::secp256k1::XOnlyPublicKey;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{client::client_with_config, Error as WsProtoError, Message as WsMessage};

use crate::nostr::{Event, KIND_SWAP};
use crate::routing::RelayConn;

/// Caps on untrusted input from a relay: a message larger than this is refused, and no more than
/// this many events are buffered (oldest dropped), so a hostile or flooding relay cannot exhaust
/// memory. Our events are a few KiB; a relay's max event is 128 KiB.
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_BUFFERED_EVENTS: usize = 10_000;

pub struct WsConn {
    outgoing: Sender<String>,
    incoming: Arc<Mutex<VecDeque<Event>>>,
    _worker: std::thread::JoinHandle<()>,
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
    pub fn connect(url: &str, socks: Option<&str>) -> Result<WsConn, WsError> {
        let (host, port, _path) = parse_ws_url(url)?;
        let stream = match socks {
            Some(proxy) => {
                crate::socks::socks5_connect(proxy, &host, port, Duration::from_secs(30))
                    .map_err(|e| WsError::Socks(e.to_string()))?
            }
            None => TcpStream::connect((host.as_str(), port)).map_err(WsError::Io)?,
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(WsError::Io)?;
        // Bound total message size (memory) but leave the frame size at the library default: a
        // too-small frame cap makes tungstenite assert rather than error on an oversized frame.
        let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE_BYTES));
        let (mut socket, _resp) = client_with_config(url, stream, Some(config))
            .map_err(|e| WsError::Handshake(e.to_string()))?;

        // Subscribe to our event kind; we filter and route client-side.
        let req = format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#);
        socket
            .send(WsMessage::Text(req.into()))
            .map_err(|e| WsError::Handshake(e.to_string()))?;

        let incoming: Arc<Mutex<VecDeque<Event>>> = Arc::default();
        let buffer = Arc::clone(&incoming);
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        let worker = std::thread::spawn(move || run(socket, rx, buffer));
        Ok(WsConn {
            outgoing: tx,
            incoming,
            _worker: worker,
        })
    }
}

/// The owner thread: drains outgoing messages, reads incoming frames, keeps the connection alive.
fn run<S: Read + Write>(
    mut socket: tungstenite::WebSocket<S>,
    rx: Receiver<String>,
    buffer: Arc<Mutex<VecDeque<Event>>>,
) {
    loop {
        while let Ok(text) = rx.try_recv() {
            if socket.send(WsMessage::Text(text.into())).is_err() {
                return;
            }
        }
        match socket.read() {
            Ok(WsMessage::Text(text)) => {
                if let Some(event) = parse_event_message(&text) {
                    let mut buf = buffer.lock().unwrap();
                    if buf.len() >= MAX_BUFFERED_EVENTS {
                        buf.pop_front();
                    }
                    buf.push_back(event);
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
            .filter(|e| e.recipient().map_or(true, |to| to == *subscriber))
            .collect()
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
}

//! A `RelayConn` over a real Nostr relay via WebSocket (NIP-01), Tor-first.
//!
//! The socket is reached directly or, by default, through a Tor SOCKS5 proxy so a relay's `.onion`
//! is dialed inside the Tor circuit; content is end-to-end encrypted by the envelope regardless, so
//! no TLS is used on the Tor path. One owner thread holds the WebSocket: it sends what `publish`
//! queues and buffers the events a `REQ` subscription returns. See design 0006.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use bitcoin::secp256k1::XOnlyPublicKey;
use tungstenite::{client::client, Message as WsMessage};

use crate::nostr::{Event, KIND_SWAP};
use crate::routing::RelayConn;

pub struct WsConn {
    outgoing: Sender<String>,
    incoming: Arc<Mutex<Vec<Event>>>,
    cursor: Mutex<usize>,
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
            Some(proxy) => socks5_connect(proxy, &host, port)?,
            None => TcpStream::connect((host.as_str(), port)).map_err(WsError::Io)?,
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(WsError::Io)?;
        let (mut socket, _resp) =
            client(url, stream).map_err(|e| WsError::Handshake(e.to_string()))?;

        // Subscribe to our event kind; we filter and route client-side.
        let req = format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#);
        socket
            .send(WsMessage::Text(req.into()))
            .map_err(|e| WsError::Handshake(e.to_string()))?;

        let incoming: Arc<Mutex<Vec<Event>>> = Arc::default();
        let buffer = Arc::clone(&incoming);
        let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();
        let worker = std::thread::spawn(move || run(socket, rx, buffer));
        Ok(WsConn {
            outgoing: tx,
            incoming,
            cursor: Mutex::new(0),
            _worker: worker,
        })
    }
}

/// The owner thread: drains outgoing messages, reads incoming frames, keeps the connection alive.
fn run<S: Read + Write>(
    mut socket: tungstenite::WebSocket<S>,
    rx: Receiver<String>,
    buffer: Arc<Mutex<Vec<Event>>>,
) {
    let mut seen = HashSet::new();
    loop {
        while let Ok(text) = rx.try_recv() {
            if socket.send(WsMessage::Text(text.into())).is_err() {
                return;
            }
        }
        match socket.read() {
            Ok(WsMessage::Text(text)) => {
                if let Some(event) = parse_event_message(&text) {
                    if seen.insert(event.id) {
                        buffer.lock().unwrap().push(event);
                    }
                }
            }
            Ok(WsMessage::Close(_)) => return,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
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
        let buffer = self.incoming.lock().unwrap();
        let mut cursor = self.cursor.lock().unwrap();
        let out = buffer
            .iter()
            .skip(*cursor)
            .filter(|e| e.pubkey != *subscriber)
            .filter(|e| e.recipient().map_or(true, |to| to == *subscriber))
            .cloned()
            .collect();
        *cursor = buffer.len();
        out
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

/// Minimal SOCKS5 client: no auth, CONNECT to a domain (so Tor resolves an `.onion`).
fn socks5_connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream, WsError> {
    let mut s = TcpStream::connect(proxy).map_err(WsError::Io)?;
    // Greeting: version 5, one method, no authentication.
    s.write_all(&[0x05, 0x01, 0x00]).map_err(WsError::Io)?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).map_err(WsError::Io)?;
    if reply != [0x05, 0x00] {
        return Err(WsError::Socks("proxy rejected no-auth".into()));
    }
    // CONNECT, address type domain.
    let host = host.as_bytes();
    if host.len() > 255 {
        return Err(WsError::Socks("host too long".into()));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).map_err(WsError::Io)?;
    // Reply: version, status, reserved, then a bound address we read and discard.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).map_err(WsError::Io)?;
    if head[1] != 0x00 {
        return Err(WsError::Socks(format!(
            "CONNECT failed, status {}",
            head[1]
        )));
    }
    let bound = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).map_err(WsError::Io)?;
            len[0] as usize + 2
        }
        _ => return Err(WsError::Socks("unknown bound address type".into())),
    };
    let mut discard = vec![0u8; bound];
    s.read_exact(&mut discard).map_err(WsError::Io)?;
    Ok(s)
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

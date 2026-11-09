//! The sovereign-swap-relay and its controls, and interop with our own WsConn client.

use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::secp256k1::{Keypair, Secp256k1};
use tungstenite::{connect, Message as WsMessage};

use sovereign_swap::nostr::{p_tag, Event, KIND_SWAP};
use sovereign_swap::relay_server::{RelayConfig, RelayServer};
use sovereign_swap::routing::RelayConn;
use sovereign_swap::ws::WsConn;

fn relay(cfg: RelayConfig) -> String {
    RelayServer::new(cfg).spawn("127.0.0.1:0").unwrap()
}

fn key(b: u8) -> Keypair {
    Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
}

/// A raw client: send one text frame, read replies for a moment.
fn send_and_read(url: &str, msg: &str) -> Vec<String> {
    let (mut ws, _) = connect(url).unwrap();
    stream_of(&ws)
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();
    ws.send(WsMessage::Text(msg.into())).unwrap();
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(600);
    while Instant::now() < deadline {
        match ws.read() {
            Ok(WsMessage::Text(t)) => out.push(t.to_string()),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    out
}

fn stream_of(
    ws: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
) -> &TcpStream {
    match ws.get_ref() {
        tungstenite::stream::MaybeTlsStream::Plain(s) => s,
        _ => unreachable!("ws:// only"),
    }
}

#[test]
fn a_valid_event_is_accepted_stored_and_served() {
    let url = relay(RelayConfig::default());
    let secp = Secp256k1::new();
    let ev = Event::build(&secp, &key(1), Event::now_for_test(), vec![], &[1, 2, 3]);
    let replies = send_and_read(&url, &format!(r#"["EVENT",{}]"#, ev.to_json()));
    assert!(
        replies
            .iter()
            .any(|r| r.contains("\"OK\"") && r.contains("true")),
        "{replies:?}"
    );

    // A later REQ gets the stored event then EOSE.
    let served = send_and_read(&url, r#"["REQ","s",{"kinds":[4859]}]"#);
    assert!(
        served.iter().any(|r| r.starts_with(r#"["EVENT","s""#)),
        "{served:?}"
    );
    assert!(served.iter().any(|r| r.starts_with(r#"["EOSE""#)));
}

#[test]
fn a_wrong_kind_is_blocked() {
    let url = relay(RelayConfig::default());
    // Hand-craft a kind-1 event's JSON (our Event only builds kind 4859), so post it raw.
    let ev = Event::build(
        &Secp256k1::new(),
        &key(2),
        Event::now_for_test(),
        vec![],
        &[9],
    );
    let kind1 = ev
        .to_json()
        .replace(&format!("\"kind\":{KIND_SWAP}"), "\"kind\":1");
    let replies = send_and_read(&url, &format!(r#"["EVENT",{kind1}]"#));
    assert!(
        replies
            .iter()
            .any(|r| r.contains("false") && r.contains("kind")),
        "{replies:?}"
    );
}

#[test]
fn a_forged_signature_is_rejected() {
    let url = relay(RelayConfig::default());
    let ev = Event::build(
        &Secp256k1::new(),
        &key(3),
        Event::now_for_test(),
        vec![],
        &[4],
    );
    // Flip a byte of the content but keep the signature: the id no longer matches.
    let forged = ev
        .to_json()
        .replacen("\"content\":\"", "\"content\":\"ff", 1);
    let replies = send_and_read(&url, &format!(r#"["EVENT",{forged}]"#));
    assert!(
        replies.iter().any(|r| r.contains("false")),
        "forged event accepted: {replies:?}"
    );
}

#[test]
fn the_rate_limit_throttles_a_flood() {
    let cfg = RelayConfig {
        max_events_per_min: 5,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    let (mut ws, _) = connect(&url).unwrap();
    stream_of(&ws)
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let secp = Secp256k1::new();
    let (mut accepted, mut rejected) = (0, 0);
    for i in 0..30u8 {
        let ev = Event::build(&secp, &key(10), Event::now_for_test(), vec![], &[i]);
        ws.send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
        if let Ok(WsMessage::Text(t)) = ws.read() {
            if t.contains("true") {
                accepted += 1;
            } else if t.contains("rate-limited") {
                rejected += 1;
            }
        }
    }
    assert!(accepted <= 7, "accepted {accepted}, limit was 5");
    assert!(rejected > 0, "nothing was rate-limited");
}

#[test]
fn our_wsconn_client_talks_to_the_relay() {
    let url = relay(RelayConfig::default());
    let maker = WsConn::connect(&url, None);
    let taker = WsConn::connect(&url, None);
    thread::sleep(Duration::from_millis(200));

    let secp = Secp256k1::new();
    let taker_route = key(20).x_only_public_key().0;
    // The maker publishes an event addressed to the taker's routing key.
    let ev = Event::build(
        &secp,
        &key(11),
        Event::now_for_test(),
        vec![p_tag(&taker_route)],
        &[7, 7],
    );
    maker.publish(ev.clone());

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = Vec::new();
    while Instant::now() < deadline && got.is_empty() {
        got.extend(taker.poll(&taker_route));
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, ev.id);
}

#[test]
fn a_slow_handshake_still_connects() {
    use std::io::{Read, Write};
    use std::thread::sleep;

    // A Tor circuit's handshake arrives well after the TCP connect. The relay must not drop it: the
    // read timeout for the message loop must not apply to the handshake. 150ms is far over the loop's
    // 50ms and under any test timeout.
    let url = relay(RelayConfig::default());
    let addr = url.trim_start_matches("ws://").trim_end_matches('/');
    let mut sock = TcpStream::connect(addr).unwrap();
    sleep(Duration::from_millis(150));
    sock.write_all(
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let mut buf = [0u8; 64];
    let n = sock.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "a slow (Tor-like) handshake was dropped: {head:?}"
    );
}

#[test]
fn an_oversized_valid_event_is_rejected_by_the_size_cap() {
    // A validly built event whose JSON exceeds max_event_bytes must be rejected with "too large".
    // This is the control the oversized/malformed attack could not reach: its event has no pubkey and
    // dies at parse, before the size check. Here the event parses, so the size cap is what stops it.
    let cfg = RelayConfig {
        max_event_bytes: 2_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    let secp = Secp256k1::new();
    let big = vec![0xAB; 1_200]; // content hex = 2400 chars, so the event JSON is over the 2000 cap
    let ev = Event::build(&secp, &key(1), Event::now_for_test(), vec![], &big);
    let replies = send_and_read(&url, &format!(r#"["EVENT",{}]"#, ev.to_json()));
    assert!(
        replies
            .iter()
            .any(|r| r.contains("\"OK\"") && r.contains("false") && r.contains("too large")),
        "oversized valid event was not rejected by the size cap: {replies:?}"
    );
}

#[test]
fn a_browser_get_gets_the_landing_page_not_a_websocket() {
    use std::io::{Read, Write};

    let url = relay(RelayConfig::default());
    // ws://127.0.0.1:PORT/ -> 127.0.0.1:PORT
    let addr = url.trim_start_matches("ws://").trim_end_matches('/');

    let mut sock = TcpStream::connect(addr).unwrap();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: relay.local\r\nAccept: text/html\r\n\r\n")
        .unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(600))).ok();

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < deadline {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.starts_with("HTTP/1.1 200 OK"),
        "status line: {text:.40}"
    );
    assert!(text.contains("text/html"), "content type missing");
    assert!(text.contains("sovereign-swap relay"), "title missing");
    assert!(
        text.contains("Do not send any coins"),
        "funds warning missing"
    );
    assert!(text.contains("4859"), "kind missing");
    // The whole page must arrive, not a truncated prefix (it was cut off over Tor when the socket
    // closed with the peeked request still unread; serve_landing now drains and half-closes).
    assert!(
        text.trim_end().ends_with("</html>"),
        "landing page truncated"
    );
}

#[test]
fn a_websocket_client_still_reaches_the_relay_after_the_landing_branch() {
    // The peek-based classifier must not disturb a real WebSocket client.
    let url = relay(RelayConfig::default());
    let secp = Secp256k1::new();
    let ev = Event::build(&secp, &key(9), Event::now_for_test(), vec![], &[4, 2]);
    let replies = send_and_read(&url, &format!(r#"["EVENT",{}]"#, ev.to_json()));
    assert!(
        replies
            .iter()
            .any(|r| r.contains("\"OK\"") && r.contains("true")),
        "websocket EVENT was not accepted: {replies:?}"
    );
}

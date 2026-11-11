//! The sovereign-swap-relay and its controls, and interop with our own WsConn client.

use std::net::TcpStream;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::hex::{Case, DisplayHex};
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

// --- Relay flood hardening (#149): per-connection REQ/subscription controls + amplification bound ---

/// A persistent raw WebSocket client that keeps its connection (and therefore its per-connection rate
/// limiter and `conn_id`) across several frames, unlike `send_and_read` which reconnects each call.
fn raw(url: &str) -> tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>> {
    let (ws, _) = connect(url).unwrap();
    stream_of(&ws)
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    ws
}

/// Reads every frame the relay sends back, until a short idle deadline.
fn drain(
    ws: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
) -> Vec<String> {
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(900);
    while Instant::now() < deadline {
        match ws.read() {
            Ok(WsMessage::Text(t)) => out.push(t.to_string()),
            Ok(_) => {}
            Err(_) => {}
        }
    }
    out
}

fn fill_store(url: &str, signer: u8, n: u8) {
    let secp = Secp256k1::new();
    let mut c = raw(url);
    for i in 0..n {
        let ev = Event::build(&secp, &key(signer), Event::now_for_test(), vec![], &[i]);
        c.send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
    }
    drain(&mut c);
}

#[test]
fn a_req_honors_the_client_limit() {
    let cfg = RelayConfig {
        max_events_per_min: 100_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    fill_store(&url, 20, 5);
    let mut c = raw(&url);
    c.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}],"limit":2}}]"#).into(),
    ))
    .unwrap();
    let out = drain(&mut c);
    let events = out.iter().filter(|l| l.starts_with(r#"["EVENT""#)).count();
    assert_eq!(
        events, 2,
        "REQ ignored the client limit: {events} events for limit 2"
    );
}

#[test]
fn a_req_is_capped_at_the_server_maximum() {
    let cfg = RelayConfig {
        max_events_per_min: 100_000,
        max_req_events: 2,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    fill_store(&url, 21, 5);
    let mut c = raw(&url);
    // No client limit: the server maximum must still bound the response.
    c.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
    ))
    .unwrap();
    let out = drain(&mut c);
    let events = out.iter().filter(|l| l.starts_with(r#"["EVENT""#)).count();
    assert!(
        events <= 2,
        "server max not enforced: {events} events streamed"
    );
}

#[test]
fn req_messages_are_rate_limited_per_connection() {
    let cfg = RelayConfig {
        max_reqs_per_min: 3,
        max_events_per_min: 100_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    let mut c = raw(&url);
    for i in 0..30 {
        c.send(WsMessage::Text(
            format!(r#"["REQ","s{i}",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
        ))
        .unwrap();
    }
    let out = drain(&mut c);
    let eose = out.iter().filter(|l| l.contains(r#""EOSE""#)).count();
    assert!(eose >= 1, "no REQ was honored at all");
    assert!(
        eose <= 8,
        "REQ flood not throttled: {eose} subscriptions accepted"
    );
}

#[test]
fn subscriptions_are_capped_per_connection() {
    let cfg = RelayConfig {
        max_subscriptions: 3,
        max_reqs_per_min: 100_000,
        max_events_per_min: 100_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    let mut c = raw(&url);
    for i in 0..8 {
        c.send(WsMessage::Text(
            format!(r#"["REQ","sub{i}",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
        ))
        .unwrap();
    }
    let out = drain(&mut c);
    let eose = out.iter().filter(|l| l.contains(r#""EOSE""#)).count();
    assert_eq!(eose, 3, "subscription cap not enforced: {eose} accepted");
}

#[test]
fn a_fresh_connection_gets_only_a_small_burst() {
    // Default per-minute allowance is large, but a cold connection must not be able to spend it all at
    // once (gap 1: a Tor reconnect otherwise hands out a full fresh bucket every time).
    let url = relay(RelayConfig::default());
    let secp = Secp256k1::new();
    let mut c = raw(&url);
    for i in 0..40u8 {
        let ev = Event::build(&secp, &key(30), Event::now_for_test(), vec![], &[i]);
        c.send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
    }
    let out = drain(&mut c);
    let accepted = out
        .iter()
        .filter(|l| l.contains(r#""OK""#) && l.contains("true"))
        .count();
    assert!(accepted >= 1, "cold connection could publish nothing");
    assert!(
        accepted <= 15,
        "cold burst too large: {accepted} accepted at once"
    );
}

/// Detects the relay closing the connection (an abrupt TCP close, or a Close frame) within `within`,
/// distinguishing it from an ordinary read timeout.
fn wait_closed(
    ws: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match ws.read() {
            Ok(WsMessage::Close(_)) => return true,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return true,
        }
    }
    false
}

#[test]
fn an_idle_connection_that_never_subscribes_is_dropped() {
    let cfg = RelayConfig {
        req_deadline_secs: 1,
        ..RelayConfig::default()
    };
    let url = relay(cfg);

    // A socket that never sends a REQ is reclaimed after the deadline (connection-cap squatter defence).
    let mut idle = raw(&url);
    assert!(
        wait_closed(&mut idle, Duration::from_secs(4)),
        "an idle, never-subscribed connection was not reclaimed"
    );

    // A connection that DID subscribe is exempt and stays open well past the same deadline.
    let mut sub = raw(&url);
    sub.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
    ))
    .unwrap();
    drain(&mut sub);
    assert!(
        !wait_closed(&mut sub, Duration::from_secs(2)),
        "a subscribed connection was wrongly dropped by the idle deadline"
    );
}

/// Publishes `n` large (~40 KB envelope) uniquely-keyed events over its own connection, draining its
/// own OK replies. Used to put enough bytes in the store / in flight to exceed loopback socket buffers.
fn fill_big(url: &str, signer: u8, n: u16, env_len: usize) {
    let secp = Secp256k1::new();
    let mut c = raw(url);
    for i in 0..n {
        let mut env = vec![0xABu8; env_len];
        // Unique content -> unique event id (dedupe would drop identical ones).
        env[0..2].copy_from_slice(&i.to_le_bytes());
        let ev = Event::build(&secp, &key(signer), Event::now_for_test(), vec![], &env);
        c.send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
    }
    drain(&mut c);
}

/// Reads until an `OK ... true` line or the deadline; returns whether the accept arrived in time.
fn got_ok(
    ws: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match ws.read() {
            Ok(WsMessage::Text(t)) if t.contains(r#""OK""#) && t.contains("true") => return true,
            Ok(_) => {}
            Err(_) => {}
        }
    }
    false
}

#[test]
fn a_non_reading_req_client_cannot_freeze_publishing() {
    let cfg = RelayConfig {
        max_events_per_min: 100_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    // Enough bytes that one backfill exceeds socket buffers (~12 x ~80 KB JSON ~ 1 MB).
    fill_big(&url, 40, 200, 50_000);

    // A REQ client that never reads its (large) backfill: its ws.send stalls on a full TCP buffer.
    let mut stuck = raw(&url);
    stuck
        .send(WsMessage::Text(
            format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
        ))
        .unwrap();
    std::thread::sleep(Duration::from_millis(400)); // let the backfill start and block on send

    // Publishing on a fresh connection must still be served promptly: the store lock is not held across
    // the stalled backfill. (With the lock held across sends, this OK never arrives in time.)
    let mut publisher = raw(&url);
    let secp = Secp256k1::new();
    let ev = Event::build(&secp, &key(41), Event::now_for_test(), vec![], &[9, 9, 9]);
    publisher
        .send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
    assert!(
        got_ok(&mut publisher, Duration::from_secs(3)),
        "a non-reading REQ client froze publishing relay-wide"
    );
}

#[test]
fn a_subscriber_whose_outbox_overflows_is_disconnected() {
    let cfg = RelayConfig {
        max_outbox_events: 1,
        max_events_per_min: 100_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);

    // Subscribe, then stop reading.
    let mut sub = raw(&url);
    sub.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
    ))
    .unwrap();
    drain(&mut sub); // consume the EOSE; now subscribed and idle

    // Flood large events from another connection so the subscriber's bounded outbox overflows.
    fill_big(&url, 42, 24, 50_000);

    // The subscriber's connection must be closed (so a real client would reconnect from `since`), not
    // left open and silently deaf.
    assert!(
        wait_closed(&mut sub, Duration::from_secs(6)),
        "an overflowed subscriber was left connected but deaf instead of being disconnected"
    );
}

#[test]
fn the_store_evicts_by_byte_budget() {
    // A small offer byte budget with a high count cap: a few large events must be evicted by BYTES,
    // long before the count cap would fire. (#149 gap 1a: bound memory, not just event count.)
    let cfg = RelayConfig {
        max_events_per_min: 100_000,
        max_store_bytes: 250_000,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    fill_big(&url, 50, 10, 50_000); // ten ~100 KB-JSON offers; the 250 KB budget holds only a couple

    let mut c = raw(&url);
    c.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
    ))
    .unwrap();
    let out = drain(&mut c);
    let events = out.iter().filter(|l| l.starts_with(r#"["EVENT""#)).count();
    assert!(events >= 1, "the store dropped everything");
    assert!(
        events < 10,
        "byte budget not enforced: all {events} large events were retained"
    );
}

#[test]
fn a_directed_flood_does_not_evict_offers() {
    // The directed store is tiny; a directed flood churns only itself and must not evict the offer,
    // which lives in its own store. (#149 gap 1b: partition offers from directed messages.)
    // Small offer cap too, so that IF partitioning were broken (directed routed into the offer store)
    // the directed flood would overflow it and evict the offer. With partitioning, the offer store only
    // ever holds the one offer.
    let cfg = RelayConfig {
        max_events_per_min: 100_000,
        store_cap: 5,
        directed_store_cap: 3,
        ..RelayConfig::default()
    };
    let url = relay(cfg);
    let secp = Secp256k1::new();

    let offer = Event::build(&secp, &key(60), Event::now_for_test(), vec![], &[1, 2, 3]);
    let offer_id = offer.id.to_hex_string(Case::Lower);
    let mut o = raw(&url);
    o.send(WsMessage::Text(
        format!(r#"["EVENT",{}]"#, offer.to_json()).into(),
    ))
    .unwrap();
    drain(&mut o);

    // Flood directed (p-tagged) events far past the directed cap.
    let route = key(61).x_only_public_key().0;
    let mut d = raw(&url);
    for i in 0..30u8 {
        let ev = Event::build(
            &secp,
            &key(62),
            Event::now_for_test(),
            vec![p_tag(&route)],
            &[i],
        );
        d.send(WsMessage::Text(
            format!(r#"["EVENT",{}]"#, ev.to_json()).into(),
        ))
        .unwrap();
    }
    drain(&mut d);

    // The offer must still be served.
    let mut c = raw(&url);
    c.send(WsMessage::Text(
        format!(r#"["REQ","s",{{"kinds":[{KIND_SWAP}]}}]"#).into(),
    ))
    .unwrap();
    let out = drain(&mut c);
    assert!(
        out.iter().any(|l| l.contains(&offer_id)),
        "a directed-message flood evicted the offer from the separate offer store"
    );
}

#[test]
fn a_rejected_publish_is_recorded_not_silently_dropped() {
    // #151: a publish the relay refuses (NIP-01 OK:false) must be observable on the client, not
    // silently swallowed. A stale event (created_at well past the retention window) is refused.
    let url = relay(RelayConfig::default());
    let conn = WsConn::connect(&url, None);
    let secp = Secp256k1::new();
    let old = Event::now_for_test().saturating_sub(30 * 24 * 3600);
    let stale = Event::build(&secp, &key(1), old, vec![], &[1, 2, 3]);
    conn.publish(stale);

    // The worker sends the event and reads the relay's OK:false asynchronously; poll briefly.
    let mut rejections = Vec::new();
    for _ in 0..40 {
        rejections = conn.take_rejections();
        if !rejections.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        rejections.iter().any(|r| r.contains("retention")),
        "a rejected publish must be recorded, got {rejections:?}"
    );
}

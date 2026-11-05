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
    let maker = WsConn::connect(&url, None).unwrap();
    let taker = WsConn::connect(&url, None).unwrap();
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

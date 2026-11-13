//! The real WebSocket path (M3b-3): RelayTransport over WsConn, against a localhost toy Nostr relay.
//! Exercises the tungstenite handshake, NIP-01 framing and routing without a network or Tor.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, PubkeyHash};
use serde_json::Value;

use sovereign_swap::envelope::Identity;
use sovereign_swap::routing::RelayTransport;
use sovereign_swap::swap::{Chain, Message, Offer};
use sovereign_swap::transport::Transport;
use sovereign_swap::ws::WsConn;

/// A minimal Nostr relay for the test: broadcasts every EVENT to every connected client and replays
/// stored events to a new REQ. One owner thread per client (read-timeout, drains an outgoing queue).
fn start_toy_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let clients: Arc<Mutex<Vec<Sender<String>>>> = Arc::default();
    let store: Arc<Mutex<Vec<String>>> = Arc::default();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (clients, store) = (Arc::clone(&clients), Arc::clone(&store));
            thread::spawn(move || serve_client(stream, clients, store));
        }
    });
    url
}

fn serve_client(
    stream: TcpStream,
    clients: Arc<Mutex<Vec<Sender<String>>>>,
    store: Arc<Mutex<Vec<String>>>,
) {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut ws = match tungstenite::accept(stream) {
        Ok(ws) => ws,
        Err(_) => return,
    };
    let (tx, rx) = mpsc::channel::<String>();
    clients.lock().unwrap().push(tx);
    loop {
        while let Ok(msg) = rx.try_recv() {
            if ws.send(tungstenite::Message::Text(msg.into())).is_err() {
                return;
            }
        }
        match ws.read() {
            Ok(tungstenite::Message::Text(text)) => {
                let v: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match v[0].as_str() {
                    Some("REQ") => {
                        for ev in store.lock().unwrap().iter() {
                            let _ = ws.send(tungstenite::Message::Text(
                                format!(r#"["EVENT","s",{ev}]"#).into(),
                            ));
                        }
                    }
                    Some("EVENT") => {
                        let ev = v[1].to_string();
                        store.lock().unwrap().push(ev.clone());
                        let line = format!(r#"["EVENT","s",{ev}]"#);
                        clients
                            .lock()
                            .unwrap()
                            .retain(|c| c.send(line.clone()).is_ok());
                    }
                    _ => {}
                }
            }
            Ok(tungstenite::Message::Close(_)) => return,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
        }
    }
}

fn party(url: &str, id_seed: u8, routing_seed: u8) -> RelayTransport<WsConn> {
    let conn = WsConn::connect(url, None);
    RelayTransport::new(
        Identity::from_seed(&[id_seed; 32]),
        &[routing_seed; 32],
        conn,
    )
}

fn offer() -> Offer {
    Offer {
        id: [42; 16],
        maker_chain: Chain::Xbtc,
        maker_amount: Amount::from_sat(1_000_000),
        taker_amount: Amount::from_sat(300_000),
        min_maker_amount: Amount::from_sat(1_000_000),
        maker_lock_blocks: 40,
        taker_lock_blocks: 20,
        maker_lock_depth: 1,
        taker_lock_depth: 1,
        margin_blocks: 2,
        fee: None,
        valid_until: None,
    }
}

/// Collects messages from `tp` until `pred` holds or the deadline passes.
fn recv_until(tp: &impl Transport, mut pred: impl FnMut(&[Message]) -> bool) -> Vec<Message> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut all = Vec::new();
    while Instant::now() < deadline {
        all.extend(tp.receive());
        if pred(&all) {
            break;
        }
        thread::sleep(Duration::from_millis(30));
    }
    all
}

#[test]
fn routing_works_over_a_real_websocket() {
    let url = start_toy_relay();
    let maker = party(&url, 1, 10);
    let taker1 = party(&url, 2, 20);
    let taker2 = party(&url, 3, 30);
    // Let every REQ subscription register before the first publish.
    thread::sleep(Duration::from_millis(200));

    maker.send(&Message::Offer(offer()));
    let seen1 = recv_until(&taker1, |m| !m.is_empty());
    let seen2 = recv_until(&taker2, |m| !m.is_empty());
    assert!(matches!(seen1.as_slice(), [Message::Offer(o)] if o.id == offer().id));
    assert!(matches!(seen2.as_slice(), [Message::Offer(o)] if o.id == offer().id));

    taker1.send(&Message::Bid {
        offer_id: offer().id,
        swap_id: [7; 16],
        maker_part: offer().maker_amount,
        taker_claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        taker_refund_pkh: PubkeyHash::from_byte_array([2; 20]),
    });
    let at_maker = recv_until(&maker, |m| !m.is_empty());
    assert!(matches!(at_maker.as_slice(), [Message::Bid { swap_id, .. }] if *swap_id == [7; 16]));
    // Taker 2 must not receive a bid addressed to the maker.
    let at_taker2 = recv_until(&taker2, |_| false);
    assert!(
        at_taker2.is_empty(),
        "a directed bid leaked to another taker"
    );
}

/// Only the author of an offer may withdraw it: a withdraw from any other party is dropped (#71).
#[test]
fn only_the_offer_author_can_withdraw_it() {
    let url = start_toy_relay();
    let maker = party(&url, 1, 10);
    let watcher = party(&url, 2, 20);
    let imposter = party(&url, 3, 30);
    thread::sleep(Duration::from_millis(200));

    // The maker publishes; the watcher learns the offer and its author.
    maker.send(&Message::Offer(offer()));
    let seen = recv_until(&watcher, |m| !m.is_empty());
    assert!(matches!(seen.as_slice(), [Message::Offer(o)] if o.id == offer().id));

    // A forged withdraw from someone who is not the author must not reach the watcher's engine.
    imposter.send(&Message::Withdraw {
        offer_id: offer().id,
    });
    let after_forged = recv_until(&watcher, |_| false);
    assert!(
        !after_forged
            .iter()
            .any(|m| matches!(m, Message::Withdraw { .. })),
        "a forged withdraw was delivered"
    );

    // The real author's withdraw is delivered.
    maker.send(&Message::Withdraw {
        offer_id: offer().id,
    });
    let after_real = recv_until(&watcher, |m| {
        m.iter().any(|x| matches!(x, Message::Withdraw { .. }))
    });
    assert!(
        after_real
            .iter()
            .any(|m| matches!(m, Message::Withdraw { offer_id } if *offer_id == offer().id)),
        "the author's own withdraw was dropped"
    );
}

//! A hostile relay must not break the client (M3c, client side of design 0003 Layer C). The client
//! drops junk, oversized and malformed frames, stays connected, and still delivers a valid event.

use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::secp256k1::{Keypair, Secp256k1};
use sovereign_swap::nostr::Event;
use sovereign_swap::routing::RelayConn;
use sovereign_swap::ws::WsConn;

/// A relay that, after the client's REQ, floods it with hostile frames and one valid event.
fn start_hostile_relay(valid: Event) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    thread::spawn(move || {
        if let Some(stream) = listener.incoming().flatten().next() {
            serve(stream, valid);
        }
    });
    url
}

fn serve(stream: TcpStream, valid: Event) {
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    // Generous limits on the relay side so it can transmit the oversized frame the client must reject.
    let config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(8 * 1024 * 1024))
        .max_frame_size(Some(8 * 1024 * 1024));
    let mut ws = match tungstenite::accept_with_config(stream, Some(config)) {
        Ok(ws) => ws,
        Err(_) => return,
    };
    // Wait for the client's REQ, then attack.
    let _ = ws.read();
    let send = |ws: &mut tungstenite::WebSocket<TcpStream>, s: String| {
        let _ = ws.send(tungstenite::Message::Text(s.into()));
    };
    send(&mut ws, "this is not json".to_owned()); // garbage
    send(&mut ws, r#"["EVENT","s",{"id":"zz"}]"#.to_owned()); // malformed event
    send(
        &mut ws,
        format!(
            r#"["EVENT","s",{{"big":"{}"}}]"#,
            "A".repeat(2 * 1024 * 1024)
        ),
    ); // oversized
    send(&mut ws, r#"["NOTICE","ignore me"]"#.to_owned()); // non-EVENT
                                                           // A well-formed event carrying a CHOSEN id that is NOT the hash of its content (here, the valid
                                                           // event's own id so it would mask it). It parses but fails verification, so the client must drop it
                                                           // at ingest; otherwise, once a client aggregates several relays (design 0029), such a forged id
                                                           // poisons the cross-relay dedup and censors the real offer. Sent BEFORE the good event so a leak
                                                           // would surface first.
    let mut forged = valid.clone();
    forged.content = "cccc".to_owned(); // change the content so the id no longer hashes to it
    send(&mut ws, format!(r#"["EVENT","s",{}]"#, forged.to_json()));
    send(&mut ws, format!(r#"["EVENT","s",{}]"#, valid.to_json())); // the one good event
                                                                    // Keep the socket open so the client's read loop continues.
    loop {
        match ws.read() {
            Ok(tungstenite::Message::Close(_)) | Err(tungstenite::Error::ConnectionClosed) => {
                return
            }
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[test]
fn a_hostile_relay_cannot_break_the_client() {
    let secp = Secp256k1::new();
    let author = Keypair::from_seckey_slice(&secp, &[5; 32]).unwrap();
    let valid = Event::build(&secp, &author, 1, vec![], &[1, 2, 3, 4]);
    let url = start_hostile_relay(valid.clone());

    let conn = WsConn::connect(&url, None);
    let subscriber = Keypair::from_seckey_slice(&secp, &[9; 32])
        .unwrap()
        .x_only_public_key()
        .0;

    // Despite the flood of junk, oversized, malformed and FORGED frames, only the one genuine event
    // arrives and the connection stays alive. Collect over a window (not just the first event) so a
    // leaked forgery, which is sent before the good event, would be caught.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut got = Vec::new();
    while Instant::now() < deadline {
        got.extend(conn.poll(&subscriber));
        thread::sleep(Duration::from_millis(30));
    }
    assert_eq!(
        got.len(),
        1,
        "only the genuine event survives the hostile flood, got {got:?}"
    );
    assert_eq!(got[0].id, valid.id);
    // The forged event masqueraded under the same id but different content; the survivor is the genuine
    // one, proving the forgery was dropped at ingest (not merely deduped by its claimed id).
    assert_eq!(
        got[0].content, valid.content,
        "the surviving event is the genuine one, not the forgery"
    );
}

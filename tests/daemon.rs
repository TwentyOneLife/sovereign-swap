//! The client daemon's local API (design 0009, M4a): auth, validation, and the scaffold endpoints.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sovereign_swap::daemon::Daemon;

static NEXT: AtomicU32 = AtomicU32::new(0);

fn daemon() -> (String, String) {
    // A unique data dir per daemon, so tests running in parallel do not share token/settings/state.
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sovswap-daemon-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Daemon::open(&dir).unwrap().spawn().unwrap()
}

/// Minimal HTTP client: send a request, return (status, body). `auth` of None omits the header.
fn request(addr: &str, method: &str, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(800))).ok();
    let auth_line = match auth {
        Some(t) => format!("Authorization: Bearer {t}\r\n"),
        None => String::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\n{auth_line}Content-Length: {len}\r\n\
         Connection: close\r\n\r\n{body}",
        len = body.len(),
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(1000);
    while Instant::now() < deadline {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status: u16 = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned();
    (status, body)
}

#[test]
fn every_route_needs_the_token() {
    let (addr, token) = daemon();
    // No header, wrong token: 401. The right token: 200.
    assert_eq!(request(&addr, "GET", "/status", None, "").0, 401);
    assert_eq!(
        request(&addr, "GET", "/status", Some("deadbeef"), "").0,
        401
    );
    assert_eq!(request(&addr, "GET", "/status", Some(&token), "").0, 200);
}

#[test]
fn settings_round_trip_and_validate() {
    let (addr, token) = daemon();
    // A clean default is readable.
    assert_eq!(request(&addr, "GET", "/settings", Some(&token), "").0, 200);

    // A valid update is accepted and then reflected.
    let good = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":["ws://a.onion:7777"],"signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
    assert_eq!(
        request(&addr, "PUT", "/settings", Some(&token), good).0,
        200
    );
    let (_, body) = request(&addr, "GET", "/settings", Some(&token), "");
    assert!(body.contains("a.onion"), "update not reflected: {body}");

    // A bad node address and a non-ws relay are each refused with reasons.
    let bad = r#"{"btc_node":"not-a-host","xbtc_node":"127.0.0.1:8442","relays":["http://nope"],"signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
    let (code, body) = request(&addr, "PUT", "/settings", Some(&token), bad);
    assert_eq!(code, 422, "bad settings not rejected: {body}");
    assert!(
        body.contains("btc_node") && body.contains("relay"),
        "no field reasons: {body}"
    );

    // Not even JSON: 400.
    assert_eq!(
        request(&addr, "PUT", "/settings", Some(&token), "nonsense").0,
        400
    );
}

#[test]
fn offers_are_validated_then_stored() {
    let (addr, token) = daemon();
    // Below dust, out-of-band price, min above amount: each rejected.
    let bad = r#"{"sell_chain":"xbtc","amount_sat":100,"price":9.9,"min_amount_sat":999999999}"#;
    let (code, body) = request(&addr, "POST", "/offers", Some(&token), bad);
    assert_eq!(code, 422, "bad offer not rejected: {body}");
    assert!(
        body.contains("amount_sat") && body.contains("price"),
        "no reasons: {body}"
    );

    // A good offer is created and then listed.
    let good =
        r#"{"sell_chain":"xbtc","amount_sat":50000000,"price":0.997,"min_amount_sat":50000000}"#;
    let (code, body) = request(&addr, "POST", "/offers", Some(&token), good);
    assert_eq!(code, 200, "good offer rejected: {body}");
    assert!(body.contains("offer_id"), "no id: {body}");
    let (_, list) = request(&addr, "GET", "/offers", Some(&token), "");
    assert!(list.contains("50000000"), "offer not listed: {list}");
}

#[test]
fn unknown_routes_and_methods_are_refused() {
    let (addr, token) = daemon();
    assert_eq!(request(&addr, "GET", "/nope", Some(&token), "").0, 404);
    assert_eq!(request(&addr, "DELETE", "/status", Some(&token), "").0, 404);
    // A path-traversal-looking id is just a 404, never a file.
    assert_eq!(
        request(&addr, "GET", "/swaps/..%2f..%2fetc", Some(&token), "").0,
        404
    );
}

#[test]
fn an_oversized_body_is_refused() {
    let (addr, token) = daemon();
    let huge = "a".repeat(128 * 1024);
    let body = format!(r#"{{"junk":"{huge}"}}"#);
    let code = request(&addr, "PUT", "/settings", Some(&token), &body).0;
    assert_eq!(code, 413, "oversized body not refused");
}

#[test]
fn btc_amounts_accept_dot_and_comma() {
    use sovereign_swap::daemon::parse_btc_to_sats;
    assert_eq!(parse_btc_to_sats("0.5"), Some(50_000_000));
    assert_eq!(parse_btc_to_sats("0,5"), Some(50_000_000)); // European decimal comma
    assert_eq!(parse_btc_to_sats("1"), Some(100_000_000));
    assert_eq!(parse_btc_to_sats("0.50000000"), Some(50_000_000));
    assert_eq!(parse_btc_to_sats("21000000"), Some(2_100_000_000_000_000));
    assert_eq!(parse_btc_to_sats(" 0,00000001 "), Some(1)); // one sat, trimmed
                                                            // refused: ambiguous grouping, sub-sat, and junk
    assert_eq!(parse_btc_to_sats("1,234.5"), None);
    assert_eq!(parse_btc_to_sats("0.123456789"), None);
    assert_eq!(parse_btc_to_sats("1.2.3"), None);
    assert_eq!(parse_btc_to_sats("abc"), None);
    assert_eq!(parse_btc_to_sats("."), None);
}

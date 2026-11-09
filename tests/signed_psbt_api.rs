//! Adversarial coverage of the `POST /swaps/{id}/signed-psbt` HTTP surface (E2, design 0017): the
//! untrusted-input edge an external attacker reaches. It checks the auth gate, path-id validation,
//! body validation, the oversize cap, and that a rejected request leaves the daemon serving. The
//! engine-level validation of the PSBT itself (same unsigned txid, fully signed, a late submit after
//! the swap abandons) lives in `tests/interactive_swap.rs`.
//!
//! No nodes are needed: the engine is not running, so once a request passes the input checks it stops
//! at the 503 "engine not running" gate, which is exactly the boundary this test pins. Runs anywhere
//! (no BTC_BITCOIND / FULCRUM_BIN), like `tests/daemon.rs`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sovereign_swap::daemon::Daemon;

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A well-formed swap id (16 bytes = 32 hex chars): passes `valid_id` and `from_hex`.
const HEX32: &str = "00112233445566778899aabbccddeeff";

fn daemon() -> (String, String) {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sovswap-psbtapi-{}-{n}", std::process::id()));
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
    let deadline = Instant::now() + Duration::from_millis(1500);
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

fn signed_psbt_path(id: &str) -> String {
    format!("/swaps/{id}/signed-psbt")
}

#[test]
fn the_signed_psbt_route_needs_the_token() {
    let (addr, token) = daemon();
    let path = signed_psbt_path(HEX32);
    let body = r#"{"psbt":"cHNidP8="}"#;
    // No header and a wrong token are both 401, before any id/body parsing.
    assert_eq!(request(&addr, "POST", &path, None, body).0, 401);
    assert_eq!(request(&addr, "POST", &path, Some("deadbeef"), body).0, 401);
    // The real token passes auth; with no engine the input is accepted up to the running-engine gate.
    assert_eq!(request(&addr, "POST", &path, Some(&token), body).0, 503);
}

#[test]
fn a_malformed_or_non_hex_swap_id_is_rejected_before_the_engine() {
    let (addr, token) = daemon();
    let body = r#"{"psbt":"cHNidP8="}"#;

    // Alphanumeric but not 32 hex: the route matches (valid_id passes) and the handler rejects the id.
    let not_hex = "z".repeat(32);
    assert_eq!(
        request(
            &addr,
            "POST",
            &signed_psbt_path(&not_hex),
            Some(&token),
            body
        )
        .0,
        400,
        "a non-hex id is a bad swap id"
    );

    // An id with an illegal character, and an over-length id, both fail valid_id so the route never
    // matches: a plain 404, never a panic or a 500.
    for bad in ["aa_bb", &"a".repeat(100)] {
        assert_eq!(
            request(&addr, "POST", &signed_psbt_path(bad), Some(&token), body).0,
            404,
            "an id failing valid_id ({bad}) must 404"
        );
    }
}

#[test]
fn a_body_that_is_not_a_psbt_object_is_rejected() {
    let (addr, token) = daemon();
    let path = signed_psbt_path(HEX32);
    // Not JSON at all.
    assert_eq!(
        request(&addr, "POST", &path, Some(&token), "not json at all").0,
        400
    );
    // JSON, but without the required `psbt` field.
    assert_eq!(
        request(&addr, "POST", &path, Some(&token), r#"{"notpsbt":1}"#).0,
        400
    );
    // Empty body.
    assert_eq!(request(&addr, "POST", &path, Some(&token), "").0, 400);
}

#[test]
fn an_oversize_body_is_capped_and_the_daemon_keeps_serving() {
    let (addr, token) = daemon();
    let path = signed_psbt_path(HEX32);
    // A body over the 64 KiB request cap: refused with 413 by the reader, never buffered unbounded.
    let huge = format!(r#"{{"psbt":"{}"}}"#, "A".repeat(70 * 1024));
    assert_eq!(
        request(&addr, "POST", &path, Some(&token), &huge).0,
        413,
        "a body over the cap is refused with 413"
    );
    // The daemon is unharmed and still answers a normal request.
    assert_eq!(request(&addr, "GET", "/status", Some(&token), "").0, 200);
}

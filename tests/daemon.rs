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
fn split_classify_is_token_gated_and_validates_its_body() {
    // Coin-split classify endpoint (P5): auth-gated like every route, and its body is validated before
    // any node I/O, so these cases never touch the Blake2b node.
    let (addr, token) = daemon();
    assert_eq!(
        request(&addr, "POST", "/split/classify", None, "{}").0,
        401,
        "classify needs the token"
    );
    assert_eq!(
        request(&addr, "POST", "/split/classify", Some(&token), "not json").0,
        400,
        "non-JSON body is 400"
    );
    assert_eq!(
        request(&addr, "POST", "/split/classify", Some(&token), "{}").0,
        422,
        "missing txid is 422"
    );
    // /split/verify: same gating + validation.
    assert_eq!(request(&addr, "POST", "/split/verify", None, "{}").0, 401);
    assert_eq!(
        request(&addr, "POST", "/split/verify", Some(&token), "nope").0,
        400
    );
    assert_eq!(
        request(&addr, "POST", "/split/verify", Some(&token), "{}").0,
        422
    );
}

#[test]
fn split_build_and_submit_are_token_gated_and_validate_their_body() {
    // Coin-split build/submit endpoints (P5): auth-gated, and the body is validated before any node I/O
    // (build) or state lookup (submit), so these cases never touch a node.
    let (addr, token) = daemon();
    // /split/build
    assert_eq!(request(&addr, "POST", "/split/build", None, "{}").0, 401);
    assert_eq!(
        request(&addr, "POST", "/split/build", Some(&token), "not json").0,
        400
    );
    assert_eq!(
        request(&addr, "POST", "/split/build", Some(&token), "{}").0,
        422,
        "missing dest is 422"
    );
    assert_eq!(
        request(
            &addr,
            "POST",
            "/split/build",
            Some(&token),
            r#"{"dest":"x"}"#
        )
        .0,
        422,
        "missing sha_coins is 422"
    );
    // /split/submit
    assert_eq!(request(&addr, "POST", "/split/submit", None, "{}").0, 401);
    assert_eq!(
        request(&addr, "POST", "/split/submit", Some(&token), "nope").0,
        400
    );
    assert_eq!(
        request(&addr, "POST", "/split/submit", Some(&token), "{}").0,
        422,
        "missing job_id/psbt is 422"
    );
    assert_eq!(
        request(
            &addr,
            "POST",
            "/split/submit",
            Some(&token),
            r#"{"job_id":"nope","psbt":"x"}"#
        )
        .0,
        410,
        "an unknown job is 410, before any node I/O"
    );
}

#[test]
fn offers_are_validated_and_need_a_running_engine() {
    let (addr, token) = daemon();
    // Input validation runs regardless of engine state: below dust, out-of-band price, min above
    // amount are each rejected with reasons (422).
    let bad = r#"{"sell_chain":"xbtc","amount_sat":100,"price":9.9,"min_amount_sat":999999999}"#;
    let (code, body) = request(&addr, "POST", "/offers", Some(&token), bad);
    assert_eq!(code, 422, "bad offer not rejected: {body}");
    assert!(
        body.contains("amount_sat") && body.contains("price"),
        "no reasons: {body}"
    );

    // A well-formed offer still cannot be published without a live engine: the daemon never
    // fabricates offers, so it returns 503 rather than storing a placeholder.
    let good = r#"{"sell_chain":"xbtc","amount_sat":50000,"price":0.997,"min_amount_sat":50000}"#;
    let (code, body) = request(&addr, "POST", "/offers", Some(&token), good);
    assert_eq!(code, 503, "offer should need a running engine: {body}");
    assert!(body.contains("engine not running"), "wrong reason: {body}");

    // Listing offers or swaps with no engine says so plainly; it never returns empty or fake data.
    for path in ["/offers", "/swaps"] {
        let (code, body) = request(&addr, "GET", path, Some(&token), "");
        assert_eq!(code, 503, "{path} should need a running engine: {body}");
    }
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
    // The size cap is in the request reader, before any route; POST /offers carries a body, so it is a
    // fine probe. The daemon refuses the oversized request with 413 rather than growing a buffer.
    let code = request(&addr, "POST", "/offers", Some(&token), &body).0;
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

#[test]
fn events_stream_needs_the_token() {
    let (addr, _) = daemon();
    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    sock.write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).unwrap_or(0);
    assert!(
        String::from_utf8_lossy(&buf[..n]).contains(" 401 "),
        "/events without a token must be 401"
    );
}

#[test]
fn events_stream_opens_as_sse() {
    let (addr, token) = daemon();
    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(300))).ok();
    sock.write_all(
        format!("GET /events HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    // The stream opens and sends the headers + initial comment; read until we have them (the server
    // writes in a couple of chunks, so a single read can race under parallel load).
    let mut text = String::new();
    let mut buf = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !text.contains(": connected") {
        match sock.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => text.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => {}
        }
    }
    assert!(
        text.contains("text/event-stream"),
        "not an SSE stream: {text}"
    );
    assert!(
        text.contains(": connected"),
        "no initial stream comment: {text}"
    );
}

#[test]
fn the_gui_is_served_with_the_token_injected() {
    let (addr, token) = daemon();
    // The page loads without the token (the browser fetches it fresh); the token is injected into it.
    let (code, body) = request(&addr, "GET", "/", None, "");
    assert_eq!(code, 200, "GUI page not served");
    assert!(
        body.contains("sovereign-swap"),
        "not the GUI html: {}",
        &body[..body.len().min(80)]
    );
    assert!(
        body.contains(&token),
        "API token not injected into the page"
    );
    assert!(
        !body.contains("__TOKEN__"),
        "token placeholder left in the page"
    );
    assert_eq!(
        request(&addr, "GET", "/app.js", None, "").0,
        200,
        "app.js not served"
    );
    assert_eq!(
        request(&addr, "GET", "/app.css", None, "").0,
        200,
        "app.css not served"
    );
}

#[test]
fn the_gui_is_served_with_security_headers() {
    // Blind spot 6: the embedded GUI document must carry clickjacking and resource-origin headers so a
    // hostile page cannot frame it or make it load/exfiltrate across origins. `request()` drops the
    // header block, so read the raw response.
    let (addr, _token) = daemon();
    let mut sock = TcpStream::connect(&addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(800))).ok();
    sock.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
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
    let text = String::from_utf8_lossy(&raw);
    let headers = text.split("\r\n\r\n").next().unwrap_or("");
    for needle in [
        "Content-Security-Policy:",
        "default-src 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "X-Frame-Options: DENY",
        "X-Content-Type-Options: nosniff",
        // script-src must be exactly 'self' with no 'unsafe-inline' (the terminating ';' proves it):
        // the GUI carries no inline script, so inline-script XSS is blocked outright.
        "script-src 'self';",
    ] {
        assert!(
            headers.contains(needle),
            "GUI response missing `{needle}` in:\n{headers}"
        );
    }
    assert!(
        !headers.contains("script-src 'self' 'unsafe-inline'"),
        "script-src must not allow 'unsafe-inline':\n{headers}"
    );
}

#[test]
fn reference_rate_is_token_guarded_and_off_by_default() {
    let (addr, token) = daemon();
    assert_eq!(request(&addr, "GET", "/reference-rate", None, "").0, 401);
    let (code, body) = request(&addr, "GET", "/reference-rate", Some(&token), "");
    assert_eq!(code, 200);
    assert!(
        body.contains("\"enabled\":false"),
        "reference must be off by default: {body}"
    );
}

/// A `min_swap_sat` below the safety floor is refused at engine bring-up (the config-load path), so
/// the fund-handling engine never runs with a leg that would be unspendable after the spend fee. The
/// gate is checked before any relay or node, so no binaries are needed.
#[test]
fn a_sub_floor_min_swap_sat_refuses_to_start_the_engine() {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sovswap-floor-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("settings.json"),
        r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":["ws://127.0.0.1:1"],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2,"min_swap_sat":2000}"#,
    )
    .unwrap();
    let daemon = Daemon::open(&dir).unwrap();
    let err = daemon.start_engine().unwrap_err();
    assert!(
        err.contains("min_swap_sat") && err.contains("safety floor"),
        "expected a min_swap_sat floor refusal, got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_daemon_on_the_same_data_dir_is_refused_then_allowed_after_release() {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sovswap-lock-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let first = Daemon::open(&dir).expect("first daemon opens");
    // A second daemon on the same data dir must refuse to start: two writers on one seed would reuse
    // key indices and secrets and double-broadcast, risking loss of funds (design 0004).
    match Daemon::open(&dir) {
        Ok(_) => panic!("a second daemon on the same data dir must be refused"),
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::AddrInUse,
            "unexpected error: {e}"
        ),
    }

    // Once the first releases the lock (dropped here), a fresh daemon can take over the same state.
    drop(first);
    let _second = Daemon::open(&dir).expect("a new daemon opens after the lock is released");

    let _ = std::fs::remove_dir_all(&dir);
}

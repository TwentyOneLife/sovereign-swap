//! HTTP/1.1 request parsing, the auth token, and small wire utilities for the daemon API.
use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use bitcoin::hex::{Case, DisplayHex, FromHex};

/// The largest request (headers + body) we read. Settings and offers are tiny; anything near this is
/// abuse, so we refuse it rather than grow a buffer.
pub(crate) const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Extracts `<id>` from `/offers/<id>/take`.
pub(crate) fn offer_id_of(path: &str) -> &str {
    path.strip_prefix("/offers/")
        .and_then(|r| r.strip_suffix("/take"))
        .unwrap_or("")
}

/// The id between `prefix` and `suffix` in a path like `/offers/<id>/withdraw`, or "" if it does not
/// fit the shape. The caller still runs `valid_id` on the result.
pub(crate) fn path_id<'a>(path: &'a str, prefix: &str, suffix: &str) -> &'a str {
    path.strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(suffix))
        .unwrap_or("")
}

pub(crate) fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b
}

pub(crate) fn load_or_make_seed(data_dir: &Path, name: &str) -> std::io::Result<[u8; 32]> {
    let path = data_dir.join(name);
    if let Ok(hex) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = <[u8; 32]>::from_hex(hex.trim()) {
            return Ok(bytes);
        }
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    std::fs::write(&path, seed.to_hex_string(Case::Lower))?;
    set_owner_only(&path);
    Ok(seed)
}

pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: Vec<u8>,
}

/// Reads one HTTP/1.1 request, size-capped. `Err(code)` is the status to answer with.
pub(crate) fn read_request<R: Read>(stream: &mut R) -> Result<Request, u16> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until the header terminator, bounded by the cap.
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(413);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(400),
        }
    };
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();
    if method.is_empty() || !path.starts_with('/') {
        return Err(400);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_len > MAX_REQUEST_BYTES {
        return Err(413);
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(400),
        }
        if body.len() > MAX_REQUEST_BYTES {
            return Err(413);
        }
    }
    body.truncate(content_len);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

pub(crate) fn load_or_make_token(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join("token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_owned();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = random_hex(32);
    std::fs::write(&path, &token)?;
    set_owner_only(&path);
    Ok(token)
}

#[cfg(unix)]
pub(crate) fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub(crate) fn set_owner_only(_path: &Path) {}

pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // Best-effort OS randomness; the token guards a loopback API, not a key.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.to_hex_string(Case::Lower)
}

/// Compares in time independent of how many leading bytes match, so the token cannot be guessed by
/// timing. Unequal lengths still run a full pass over the presented bytes.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for (i, &byte) in a.iter().enumerate() {
        diff |= byte ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// An id we will echo into a path or a response: hex-ish, bounded, no path tricks.
pub(crate) fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A cheap health hint for the GUI: can we open a TCP connection to the node. Accepts a node address
/// in any form (bare `host:port`, `http://`, `https://`). An `.onion` is never probed directly (that
/// would resolve and leak the name outside Tor), so it is reported reachable and the real check is the
/// first RPC call through the proxy.
pub(crate) fn reachable(addr: &str) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(endpoint) = crate::rpc::parse_endpoint(addr) else {
        return false;
    };
    if endpoint.is_onion() {
        return true;
    }
    endpoint
        .host_port()
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok())
        .unwrap_or(false)
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

#[cfg(test)]
mod fuzz {
    use super::{read_request, MAX_REQUEST_BYTES};
    use std::io::Cursor;

    /// The HTTP request parser reads attacker-controlled bytes off the socket; it must never panic and
    /// must refuse an oversized Content-Length rather than allocate it.
    #[test]
    fn read_request_never_panics_on_random_or_malformed_input() {
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..20_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let n = (s % 4096) as usize;
            let mut bytes = Vec::with_capacity(n);
            for _ in 0..n {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                bytes.push((s & 0xff) as u8);
            }
            let _ = read_request(&mut Cursor::new(bytes));
        }
        for c in [
            "",
            "GET",
            "GET /\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\nx",
            "GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            "\r\n\r\n",
            "GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
            "PUT / HTTP/1.1\r\n: v\r\nX:\r\n\r\n",
        ] {
            let _ = read_request(&mut Cursor::new(c.as_bytes().to_vec()));
        }
        // An oversized Content-Length is rejected (413), never allocated.
        let big = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_REQUEST_BYTES + 1
        );
        assert!(matches!(
            read_request(&mut Cursor::new(big.into_bytes())),
            Err(413)
        ));
    }
}

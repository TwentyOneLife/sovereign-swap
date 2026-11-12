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
/// Reads and parses one HTTP/1.1 request. `deadline`, when set, is an ABSOLUTE wall-clock bound on the
/// whole read: once it passes, the read is abandoned with 408. This is the slowloris defence. The
/// socket's own per-read timeout only bounds a single `read` call, so a connection that dribbles one
/// byte before each timeout resets it forever and can hold a connection-table slot indefinitely; the
/// absolute deadline is what actually caps that. A per-read timeout that fires (`WouldBlock`/`TimedOut`)
/// is therefore not fatal while the deadline has room: we loop back to re-check it, so the caller should
/// set a socket read timeout well under the deadline so a stalled read wakes to be cut. `None` (the
/// fuzz/in-memory path, where reads never block) keeps the original behaviour.
pub(crate) fn read_request<R: Read>(
    stream: &mut R,
    deadline: Option<std::time::Instant>,
) -> Result<Request, u16> {
    let timed_out = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until the header terminator, bounded by the cap and the deadline.
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(413);
        }
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Err(408);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // A per-read timeout is not fatal while the deadline has room: re-check and retry.
            Err(ref e) if deadline.is_some() && timed_out(e) => continue,
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
        if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            return Err(408);
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(ref e) if deadline.is_some() && timed_out(e) => continue,
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
        408 => "Request Timeout",
        404 => "Not Found",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;
    use std::time::{Duration, Instant};

    /// A `Read` that plays a scripted sequence of results. `Ok(bytes)` yields those bytes (empty = EOF),
    /// `Err` yields that error; once the script is empty it returns `WouldBlock`, standing in for a
    /// socket whose per-read timeout keeps firing (a slowloris dribble).
    struct ScriptReader(VecDeque<io::Result<Vec<u8>>>);
    impl Read for ScriptReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                Some(Ok(data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                }
                Some(Err(e)) => Err(e),
                None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        }
    }
    fn wb() -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::WouldBlock))
    }

    #[test]
    fn read_request_aborts_at_the_deadline_rather_than_holding_the_slot() {
        // A slowloris: a partial header line, then reads that keep timing out (WouldBlock) and would
        // never complete the headers. With the deadline already reached, read_request must give up
        // with 408 instead of looping forever and holding the connection slot.
        let mut r = ScriptReader(
            [
                Ok(b"GET / HTTP/1.1\r\n".to_vec()),
                wb(),
                wb(),
                Ok(Vec::new()),
            ]
            .into_iter()
            .collect(),
        );
        // A deadline captured now has passed by the time the loop checks it.
        match read_request(&mut r, Some(Instant::now())) {
            Err(code) => assert_eq!(code, 408, "a timed-out read must be 408"),
            Ok(_) => panic!("expected a 408 timeout, not a parsed request"),
        }
    }

    #[test]
    fn read_request_retries_through_read_timeouts_while_the_deadline_has_room() {
        // A healthy client whose bytes arrive across reads that time out in between: the per-read
        // timeouts are not fatal while the deadline has room, so the request still parses.
        let mut r = ScriptReader(
            [
                wb(),
                Ok(b"POST /offers HTTP/1.1\r\n".to_vec()),
                wb(),
                Ok(b"Content-Length: 2\r\n\r\nhi".to_vec()),
            ]
            .into_iter()
            .collect(),
        );
        let req = read_request(&mut r, Some(Instant::now() + Duration::from_secs(30)))
            .expect("should parse across read timeouts");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/offers");
        assert_eq!(req.body, b"hi");
    }

    #[test]
    fn read_request_without_a_deadline_parses_a_whole_request() {
        // The in-memory / fuzz path (no deadline, reads never block) keeps the original behaviour.
        let mut r = io::Cursor::new(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
        let req = read_request(&mut r, None).expect("plain request parses");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/status");
    }
}

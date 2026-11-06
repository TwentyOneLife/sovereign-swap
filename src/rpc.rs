//! JSON-RPC client for a bitcoind (Core or Knots), direct or over Tor, plain HTTP or HTTPS.
//!
//! A StartOS node does not publish plain `http://host:8332`; it fronts bitcoind's RPC with a TLS
//! proxy and serves it as HTTPS on a dedicated port, reachable over the LAN or a Tor onion (design
//! 0011). This client therefore speaks three transports behind one `call`:
//!
//! - plain HTTP to a `host:port` (the historical local case, still the default),
//! - HTTPS verified against a caller-supplied Root CA (the StartOS Root CA, for a LAN address),
//! - HTTPS to a `.onion`, dialed through a SOCKS5 proxy; the onion address authenticates the
//!   endpoint, so the self-signed certificate is accepted while the handshake signature is still
//!   checked.
//!
//! The crypto is `rustls` with the audited `ring` provider; this module invents none. The HTTP is
//! hand-written and minimal (one request per call, `Connection: close`), as before.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::OutPoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, IpAddr, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};
use serde_json::{json, Value};

use crate::replay::UtxoLookup;
use crate::socks::socks5_connect;

/// Per-call network budget. Generous because an onion round trip is slow and a circuit can stall; a
/// local HTTP call returns in milliseconds and is unaffected.
const TIMEOUT: Duration = Duration::from_secs(120);

/// Bounds opening the connection (direct TCP connect, or the whole SOCKS proxy handshake). Shorter
/// than `TIMEOUT`: a node that will not even accept a connection must fail fast, never hang the
/// engine thread and starve a refund (design 0011).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest response we will read from a node: bitcoind replies are small, but a large wallet listing
/// can run to a few MiB. A hostile endpoint cannot make us buffer without bound.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum RpcError {
    Io(std::io::Error),
    Http(String),
    Tls(String),
    Config(String),
    Json(serde_json::Error),
    Rpc { code: i64, message: String },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Scheme {
    Http,
    Https,
}

/// A parsed node endpoint: scheme, host, port. `onion` is cached because it decides both transport
/// (SOCKS is mandatory) and TLS policy (accept the presented certificate).
#[derive(Clone, Debug)]
pub struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl Endpoint {
    pub fn is_onion(&self) -> bool {
        is_onion(&self.host)
    }

    pub fn is_https(&self) -> bool {
        self.scheme == Scheme::Https
    }

    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn server_name(&self) -> Result<ServerName<'static>, RpcError> {
        // An IP literal is verified against the certificate's IP SAN (the StartOS LAN cert carries
        // one); a name is sent as itself. rustls omits SNI for an IP, as it should.
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            Ok(ServerName::IpAddress(IpAddr::from(ip)))
        } else {
            ServerName::try_from(self.host.clone()).map_err(|_| {
                RpcError::Config(format!("not a valid TLS server name: {}", self.host))
            })
        }
    }
}

/// Parses a node address into an endpoint. A bare `host:port` is treated as `http://host:port`, so
/// saved local settings keep working; `http://` and `https://` are explicit.
pub fn parse_endpoint(addr: &str) -> Result<Endpoint, RpcError> {
    let (scheme, rest) = if let Some(rest) = addr.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = addr.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        (Scheme::Http, addr)
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') {
        return Err(RpcError::Config("node address has a path".to_owned()));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| RpcError::Config("node address needs host:port".to_owned()))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| RpcError::Config("node address needs a valid port".to_owned()))?;
    // Lowercase and drop a trailing root dot so onion detection cannot be dodged by case or an FQDN
    // dot (`X.ONION.` must still route through Tor, not a local resolver). Safe for a host: DNS and
    // onion names are case-insensitive, and an IP literal is unaffected.
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(RpcError::Config("node address needs a host".to_owned()));
    }
    Ok(Endpoint { scheme, host, port })
}

pub fn is_onion(host: &str) -> bool {
    host.ends_with(".onion")
}

#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    path: String,
    authorization: String,
    /// SOCKS5 proxy to dial through; always set for an onion, never for a direct address.
    socks: Option<String>,
    /// Present iff the scheme is HTTPS. Built once and shared across calls.
    tls: Option<Arc<ClientConfig>>,
}

impl Client {
    /// A plain-HTTP client to `host:port`, no TLS and no proxy. The historical local-node path, kept
    /// for tests and a co-resident node reached over the loopback.
    pub fn new(host_port: &str, user: &str, password: &str) -> Client {
        Client::connect(&format!("http://{host_port}"), user, password, None, None)
            .expect("a plain-http endpoint cannot fail to build")
    }

    /// Builds a client for `addr` (a `host:port`, `http://...` or `https://...`). `ca` is a PEM Root
    /// CA to verify an HTTPS endpoint against; pass `None` to accept the certificate of an onion
    /// (where Tor authenticates the endpoint). `socks` is the proxy to dial through; required for an
    /// onion. The rules are enforced here so a misconfiguration fails at open, not mid-swap.
    pub fn connect(
        addr: &str,
        user: &str,
        password: &str,
        ca: Option<&str>,
        socks: Option<&str>,
    ) -> Result<Client, RpcError> {
        let endpoint = parse_endpoint(addr)?;
        let onion = endpoint.is_onion();
        if onion && socks.is_none() {
            return Err(RpcError::Config(
                "an .onion node needs a Tor SOCKS proxy".to_owned(),
            ));
        }
        // build_tls enforces the CA rule for https (a non-onion https with no CA is refused there).
        let tls = match endpoint.scheme {
            Scheme::Http => None,
            Scheme::Https => Some(Arc::new(build_tls(ca, onion)?)),
        };
        Ok(Client {
            endpoint,
            path: "/".to_owned(),
            authorization: base64(format!("{user}:{password}").as_bytes()),
            socks: socks.map(str::to_owned),
            tls,
        })
    }

    pub fn host_port(&self) -> String {
        self.endpoint.host_port()
    }

    pub fn wallet(&self, name: &str) -> Client {
        Client {
            path: format!("/wallet/{name}"),
            ..self.clone()
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body =
            json!({ "jsonrpc": "1.0", "id": 0, "method": method, "params": params }).to_string();
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.path,
            self.host_port(),
            self.authorization,
            body.len(),
            body
        );

        let tcp = match &self.socks {
            Some(proxy) => socks5_connect(
                proxy,
                &self.endpoint.host,
                self.endpoint.port,
                CONNECT_TIMEOUT,
            ),
            None => connect_direct(&self.endpoint.host, self.endpoint.port),
        }
        .map_err(RpcError::Io)?;
        tcp.set_read_timeout(Some(TIMEOUT)).map_err(RpcError::Io)?;
        tcp.set_write_timeout(Some(TIMEOUT)).map_err(RpcError::Io)?;

        let (status, payload) = match &self.tls {
            Some(config) => {
                let conn = ClientConnection::new(config.clone(), self.endpoint.server_name()?)
                    .map_err(|e| RpcError::Tls(e.to_string()))?;
                let mut stream = StreamOwned::new(conn, tcp);
                exchange(&mut stream, request.as_bytes())?
            }
            None => {
                let mut stream = tcp;
                exchange(&mut stream, request.as_bytes())?
            }
        };
        decode(status, &payload)
    }
}

/// Opens a direct TCP connection with a bounded connect, so an unreachable local node fails fast
/// instead of hanging on the OS default (design 0011, same reason as the SOCKS timeout).
fn connect_direct(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("node address did not resolve"))?;
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
}

/// Writes the request and reads the response off one stream (TLS or plain), returning status and body.
fn exchange<S: Read + Write>(stream: &mut S, request: &[u8]) -> Result<(u16, Vec<u8>), RpcError> {
    stream.write_all(request).map_err(write_err)?;
    stream.flush().map_err(write_err)?;
    read_response(BufReader::new(stream))
}

/// A write to a TLS stream surfaces a certificate or handshake failure here; label it so the caller
/// sees "TLS" rather than a bare I/O error.
fn write_err(e: std::io::Error) -> RpcError {
    if e.get_ref().is_some() {
        RpcError::Tls(e.to_string())
    } else {
        RpcError::Io(e)
    }
}

/// Reads an HTTP/1.1 response: status line, headers, then the body by Content-Length or chunked
/// transfer-encoding. Reading to EOF is a last resort, and a clean TLS close that omits `close_notify`
/// is treated as a normal end of body, not an error.
fn read_response<R: Read>(mut reader: BufReader<R>) -> Result<(u16, Vec<u8>), RpcError> {
    let mut line = String::new();
    reader.read_line(&mut line).map_err(read_err)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| RpcError::Http(format!("no status in {:?}", line.trim())))?;

    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(read_err)? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if name == "content-length" {
                content_length = value.parse::<u64>().ok();
            } else if name == "transfer-encoding" && value.eq_ignore_ascii_case("chunked") {
                chunked = true;
            }
        }
    }

    let body = if chunked {
        read_chunked(&mut reader)?
    } else if let Some(len) = content_length {
        if len > MAX_RESPONSE_BYTES {
            return Err(RpcError::Http("response too large".to_owned()));
        }
        let mut buf = vec![0u8; len as usize];
        read_exact_eof_ok(&mut reader, &mut buf)?;
        buf
    } else {
        let mut buf = Vec::new();
        reader
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut buf)
            .or_else(eof_ok)
            .map_err(read_err)?;
        buf
    };
    Ok((status, body))
}

/// Maps the response status and body to an RPC result. bitcoind returns a JSON body even on a non-200
/// (a method error is 404 or 500 with `{"error":{...}}`), so a JSON body is always parsed and its
/// `error` field, not the HTTP status, decides success. A 401 (bad RPC credentials) and any non-JSON
/// body are reported as HTTP errors, not as a confusing JSON parse error.
fn decode(status: u16, payload: &[u8]) -> Result<Value, RpcError> {
    if status == 401 {
        return Err(RpcError::Http(
            "HTTP 401 Unauthorized (check the node RPC username and password)".to_owned(),
        ));
    }
    if payload.is_empty() {
        return Err(RpcError::Http(format!("HTTP {status}, empty body")));
    }
    let mut reply: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        // A non-JSON body on a non-200 is an HTTP/proxy-layer problem, not an RPC one; surface the
        // status rather than a parse error. A non-JSON 200 is a genuine decode failure.
        Err(_) if status != 200 => return Err(RpcError::Http(format!("HTTP {status}"))),
        Err(e) => return Err(RpcError::Json(e)),
    };
    if let Some(err) = reply.get("error").filter(|e| !e.is_null()) {
        return Err(RpcError::Rpc {
            code: err["code"].as_i64().unwrap_or_default(),
            message: err["message"].as_str().unwrap_or_default().to_owned(),
        });
    }
    Ok(reply["result"].take())
}

fn read_chunked<R: Read>(reader: &mut BufReader<R>) -> Result<Vec<u8>, RpcError> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).map_err(read_err)? == 0 {
            break;
        }
        let size = usize::from_str_radix(size_line.trim(), 16)
            .map_err(|_| RpcError::Http("bad chunk size".to_owned()))?;
        if size == 0 {
            break;
        }
        if body.len() + size > MAX_RESPONSE_BYTES as usize {
            return Err(RpcError::Http("response too large".to_owned()));
        }
        let mut chunk = vec![0u8; size];
        read_exact_eof_ok(reader, &mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf);
    }
    Ok(body)
}

/// Fills `buf`, but a TLS peer that closes without `close_notify` (common for these proxies) having
/// already delivered the whole body is not an error.
fn read_exact_eof_ok<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), RpcError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if is_eof(&e) => break,
            Err(e) => return Err(read_err(e)),
        }
    }
    Ok(())
}

fn eof_ok(e: std::io::Error) -> std::io::Result<usize> {
    if is_eof(&e) {
        Ok(0)
    } else {
        Err(e)
    }
}

/// rustls surfaces a missing `close_notify` as `UnexpectedEof`; many TLS proxies close that way.
fn is_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}

fn read_err(e: std::io::Error) -> RpcError {
    if e.get_ref().is_some() {
        RpcError::Tls(e.to_string())
    } else {
        RpcError::Io(e)
    }
}

/// Builds the TLS client config. With a CA, verify the chain and the name/IP against it (the LAN
/// case). Without one, for an onion, accept the presented certificate but still verify the handshake
/// signature, since Tor already authenticates the endpoint. A non-onion HTTPS without a CA is
/// rejected before this is reached.
fn build_tls(ca: Option<&str>, onion: bool) -> Result<ClientConfig, RpcError> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| RpcError::Config(e.to_string()))?;
    match ca {
        Some(pem) => {
            let mut roots = RootCertStore::empty();
            let mut added = 0usize;
            for der in rustls_pemfile::certs(&mut pem.as_bytes()) {
                let der = der.map_err(|e| RpcError::Config(format!("bad CA PEM: {e}")))?;
                roots
                    .add(der)
                    .map_err(|e| RpcError::Config(format!("bad CA certificate: {e}")))?;
                added += 1;
            }
            if added == 0 {
                return Err(RpcError::Config("CA PEM held no certificate".to_owned()));
            }
            Ok(builder.with_root_certificates(roots).with_no_client_auth())
        }
        None if onion => {
            let verifier = Arc::new(OnionCertVerifier {
                supported: provider.signature_verification_algorithms,
            });
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth())
        }
        None => Err(RpcError::Config(
            "https without a Root CA is only allowed for an onion".to_owned(),
        )),
    }
}

/// Accepts any server certificate but still verifies the TLS handshake signature with the `ring`
/// provider's algorithms. Sound only over an authenticated transport (a Tor onion address is its own
/// key): the onion names the endpoint, so the certificate need not. Never used on the LAN path.
#[derive(Debug)]
struct OnionCertVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for OnionCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

impl UtxoLookup for Client {
    type Error = RpcError;

    fn is_unspent(&self, outpoint: &OutPoint) -> Result<bool, RpcError> {
        let txout = self.call(
            "gettxout",
            json!([outpoint.txid.to_string(), outpoint.vout, true]),
        )?;
        Ok(!txout.is_null())
    }
}

pub(crate) fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(super::base64(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn parse_endpoint_schemes_and_defaults() {
        let e = parse_endpoint("127.0.0.1:8332").unwrap();
        assert_eq!(
            (e.scheme, e.host.as_str(), e.port),
            (Scheme::Http, "127.0.0.1", 8332)
        );
        let e = parse_endpoint("https://node.onion:65494").unwrap();
        assert!(e.is_onion() && e.scheme == Scheme::Https && e.port == 65494);
        let e = parse_endpoint("http://host:1/").unwrap();
        assert_eq!(e.port, 1);
        assert!(parse_endpoint("host-without-port").is_err());
        assert!(parse_endpoint("http://host:0").is_err());
        assert!(parse_endpoint("http://host:9/path").is_err());
    }

    #[test]
    fn connect_enforces_transport_rules() {
        // onion needs a proxy
        assert!(matches!(
            Client::connect("https://abc.onion:8332", "u", "p", None, None),
            Err(RpcError::Config(_))
        ));
        // https to a non-onion needs a CA (192.0.2.0/24 is the RFC 5737 documentation range)
        assert!(matches!(
            Client::connect("https://192.0.2.2:8332", "u", "p", None, None),
            Err(RpcError::Config(_))
        ));
        // plain http is always fine
        assert!(Client::connect("http://127.0.0.1:8332", "u", "p", None, None).is_ok());
    }
}

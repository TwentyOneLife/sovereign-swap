//! Transport tests for the node RPC client (design 0011): HTTPS verified against a Root CA, a wrong
//! CA rejected, a JSON error body on a non-200, chunked framing, a TLS close without `close_notify`,
//! and SOCKS5 remote-DNS dialing. The certificate and key are minted in-process with `rcgen` (a
//! dev-dependency); nothing is committed to the repo.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use sovereign_swap::rpc::{Client, RpcError};

/// A minted CA (as PEM) plus the leaf chain and key a test server presents.
struct Minted {
    ca_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// Mints a self-signed CA and a `127.0.0.1` leaf (IP SAN) signed by it, mirroring the StartOS shape
/// (a self-signed Root CA and a leaf with an IP SAN) the client must trust on the LAN.
fn mint() -> Minted {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    // A string that parses as an IP becomes an IP SAN in rcgen, matching the live cert.
    let leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

    Minted {
        ca_pem: ca.pem(),
        chain: vec![leaf.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// Spawns a one-shot TLS server on 127.0.0.1 that completes the handshake, reads the request, writes
/// `response` verbatim, and if `abrupt` drops the TCP socket without a TLS `close_notify`. Returns the
/// bound port.
fn tls_server(minted: &Minted, response: Vec<u8>, abrupt: bool) -> u16 {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(minted.chain.clone(), minted.key.clone_key())
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(config).unwrap();
        let mut stream = StreamOwned::new(conn, tcp);
        // Read the request head (up to the blank line) so the client's write completes.
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        if abrupt {
            let _ = stream.sock.shutdown(Shutdown::Both);
        }
    });
    port
}

fn http(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn https_with_matching_ca_succeeds() {
    let m = mint();
    let port = tls_server(
        &m,
        http("200 OK", r#"{"result":123,"error":null,"id":0}"#),
        false,
    );
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&m.ca_pem),
        None,
    )
    .unwrap();
    let got = client.call("getblockcount", serde_json::json!([])).unwrap();
    assert_eq!(got.as_i64(), Some(123));
}

#[test]
fn https_with_wrong_ca_is_rejected() {
    let server = mint();
    let other = mint(); // a different CA the client will trust instead
    let port = tls_server(
        &server,
        http("200 OK", r#"{"result":1,"error":null,"id":0}"#),
        false,
    );
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&other.ca_pem),
        None,
    )
    .unwrap();
    let err = client
        .call("getblockcount", serde_json::json!([]))
        .unwrap_err();
    assert!(
        matches!(err, RpcError::Tls(_)),
        "expected TLS error, got {err:?}"
    );
}

#[test]
fn json_error_body_on_non_200_maps_to_rpc_error() {
    let m = mint();
    // bitcoind returns a JSON error with a non-200 (here 500); the body, not the status, decides.
    let body = r#"{"result":null,"error":{"code":-27,"message":"already in chain"},"id":0}"#;
    let port = tls_server(&m, http("500 Internal Server Error", body), false);
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&m.ca_pem),
        None,
    )
    .unwrap();
    let err = client
        .call("sendrawtransaction", serde_json::json!([]))
        .unwrap_err();
    match err {
        RpcError::Rpc { code, message } => {
            assert_eq!(code, -27);
            assert!(message.contains("already"));
        }
        other => panic!("expected RpcError::Rpc, got {other:?}"),
    }
}

#[test]
fn chunked_body_is_decoded() {
    let m = mint();
    let json = r#"{"result":"ok","error":null,"id":0}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{json}\r\n0\r\n\r\n",
        json.len()
    )
    .into_bytes();
    let port = tls_server(&m, response, false);
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&m.ca_pem),
        None,
    )
    .unwrap();
    let got = client.call("x", serde_json::json!([])).unwrap();
    assert_eq!(got.as_str(), Some("ok"));
}

#[test]
fn close_without_close_notify_still_yields_body() {
    let m = mint();
    // A Content-Length body, then the socket is dropped with no TLS close_notify.
    let port = tls_server(
        &m,
        http("200 OK", r#"{"result":7,"error":null,"id":0}"#),
        true,
    );
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&m.ca_pem),
        None,
    )
    .unwrap();
    let got = client.call("getblockcount", serde_json::json!([])).unwrap();
    assert_eq!(got.as_i64(), Some(7));
}

/// A one-shot SOCKS5 proxy on 127.0.0.1 that asserts the client sent a *domain* address (ATYP 0x03,
/// i.e. it asked the proxy to resolve the name, socks5h) equal to `expect_host`, then relays raw
/// bytes to `backend_port`. Used for both the plaintext and the TLS-over-Tor cases. Returns the port.
fn socks_proxy(expect_host: &'static [u8], backend_port: u16) -> u16 {
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = proxy.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut c, _) = proxy.accept().unwrap();
        let mut greet = [0u8; 3];
        c.read_exact(&mut greet).unwrap();
        assert_eq!(greet, [0x05, 0x01, 0x00]);
        c.write_all(&[0x05, 0x00]).unwrap();
        let mut head = [0u8; 4];
        c.read_exact(&mut head).unwrap();
        assert_eq!(head[3], 0x03, "client must send a domain (remote DNS)");
        let mut len = [0u8; 1];
        c.read_exact(&mut len).unwrap();
        let mut host = vec![0u8; len[0] as usize];
        c.read_exact(&mut host).unwrap();
        assert_eq!(host, expect_host, "proxy saw the wrong host");
        let mut discard_port = [0u8; 2];
        c.read_exact(&mut discard_port).unwrap();
        c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let mut back = TcpStream::connect(("127.0.0.1", backend_port)).unwrap();
        let mut c2 = c.try_clone().unwrap();
        let mut b2 = back.try_clone().unwrap();
        let up = thread::spawn(move || std::io::copy(&mut c, &mut back));
        let _ = std::io::copy(&mut b2, &mut c2);
        let _ = up.join();
    });
    port
}

/// Plain HTTP over SOCKS5: the onion name is resolved by the proxy, never locally.
#[test]
fn socks5_uses_remote_dns_and_relays() {
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut tcp, _) = backend.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = tcp.read(&mut buf);
        let _ = tcp.write_all(&http(
            "200 OK",
            r#"{"result":"viaproxy","error":null,"id":0}"#,
        ));
    });
    let proxy = format!(
        "127.0.0.1:{}",
        socks_proxy(b"swap-node.onion", backend_port)
    );
    let client =
        Client::connect("http://swap-node.onion:8332", "u", "p", None, Some(&proxy)).unwrap();
    let got = client.call("getblockcount", serde_json::json!([])).unwrap();
    assert_eq!(got.as_str(), Some("viaproxy"));
}

/// The shipped default path: HTTPS to an onion over SOCKS5 with no CA, so `OnionCertVerifier` accepts
/// the self-signed certificate (Tor authenticates the endpoint) while still verifying the handshake
/// signature. The TLS backend runs behind the relaying proxy, exactly as a node's RPC onion would.
#[test]
fn https_onion_over_socks_accepts_cert() {
    let m = mint();
    let backend_port = tls_server(
        &m,
        http("200 OK", r#"{"result":42,"error":null,"id":0}"#),
        false,
    );
    let proxy = format!(
        "127.0.0.1:{}",
        socks_proxy(b"swap-node.onion", backend_port)
    );
    let client =
        Client::connect("https://swap-node.onion:8332", "u", "p", None, Some(&proxy)).unwrap();
    let got = client.call("getblockcount", serde_json::json!([])).unwrap();
    assert_eq!(got.as_i64(), Some(42));
}

/// Live check against a real StartOS bitcoind RPC, driven entirely by environment so no node address
/// ever enters the repo. Ignored by default; run it explicitly against a reachable node:
///
/// ```text
/// SWAP_LIVE_URL=https://<host>:<port> SWAP_LIVE_CA_FILE=/path/root-ca.pem \
/// SWAP_LIVE_USER=__cookie__ SWAP_LIVE_PASS=<cookie-hex> \
/// cargo test --test rpc_transport -- --ignored --exact live_node_rpc_roundtrip --nocapture
/// ```
///
/// It proves the client, not just the endpoint: a real Ed25519 leaf behind a two-tier StartOS CA,
/// HTTP Basic auth, and wallet-path forwarding. It only reads chain state and queries a non-existent
/// wallet, so it writes nothing to the node.
#[test]
#[ignore = "needs a reachable live node; set SWAP_LIVE_* env"]
fn live_node_rpc_roundtrip() {
    let url = std::env::var("SWAP_LIVE_URL").expect("SWAP_LIVE_URL");
    let user = std::env::var("SWAP_LIVE_USER").unwrap_or_else(|_| "__cookie__".to_string());
    let pass = std::env::var("SWAP_LIVE_PASS").expect("SWAP_LIVE_PASS");
    let ca = std::env::var("SWAP_LIVE_CA_FILE")
        .ok()
        .map(|p| std::fs::read_to_string(p).expect("CA PEM file"));

    // 1. getblockcount over verified HTTPS.
    let client = Client::connect(&url, &user, &pass, ca.as_deref(), None).expect("connect");
    let height = client
        .call("getblockcount", serde_json::json!([]))
        .expect("getblockcount");
    let height = height.as_u64().expect("height is a number");
    println!("live getblockcount = {height}");
    assert!(height > 0, "a synced node has a positive height");

    // 2. wrong credentials fail with a clear error, not a JSON parse error.
    let bad = Client::connect(&url, &user, "definitely-wrong", ca.as_deref(), None).unwrap();
    match bad.call("getblockcount", serde_json::json!([])) {
        Err(RpcError::Http(m)) => println!("bad-cred -> HTTP error as expected: {m}"),
        other => panic!("bad credentials should be an HTTP error, got {other:?}"),
    }

    // 3. the proxy forwards wallet paths: a missing wallet yields RPC error -18, writing nothing.
    let wallet = client.wallet("sovereign-swap-does-not-exist");
    match wallet.call("getwalletinfo", serde_json::json!([])) {
        Err(RpcError::Rpc { code, .. }) => {
            assert_eq!(code, -18, "expected 'wallet not found' (-18)");
            println!("wallet-path forwarding confirmed (-18)");
        }
        other => panic!("expected RPC -18 for a missing wallet, got {other:?}"),
    }
}

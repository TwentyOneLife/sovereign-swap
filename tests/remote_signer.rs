//! `RemoteSigner` against a mock signer endpoint (design 0012). Proves the cold signing seam over
//! the real node transport: a sign, a typed refusal, a transport timeout, a malformed reply (missing
//! PSBT and a swapped transaction), and the reachability probe. The TLS cases mint a throwaway CA and
//! leaf in-process with `rcgen`, exactly as `rpc_transport.rs` does, so nothing is committed to the
//! repo; the timeout and unreachable cases use a plain-TCP mock, which is enough to exercise the
//! timeout and connection-refused paths.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use sovereign_swap::node::{FundingSigner, NodeError, SignerError};
use sovereign_swap::rpc::Client;
use sovereign_swap::signer::RemoteSigner;

/// A base64 PSBT over a one-input, one-output transaction whose single output pays `sats`. Changing
/// `sats` changes the transaction (a different txid), which is how the "swapped transaction" test
/// builds a reply the signer must not be allowed to return.
fn psbt_paying(sats: u64) -> String {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    Psbt::from_unsigned_tx(tx).unwrap().to_string()
}

/// A JSON-RPC 1.0 result body (HTTP 200), the shape bitcoind and so the mock signer use.
fn ok_body(result: &str) -> Vec<u8> {
    http(
        "200 OK",
        &format!(r#"{{"result":{result},"error":null,"id":0}}"#),
    )
}

fn http(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

// --- TLS mock, mirroring tests/rpc_transport.rs ------------------------------------------------

struct Minted {
    ca_pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn mint() -> Minted {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Minted {
        ca_pem: ca.pem(),
        chain: vec![leaf.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// A one-shot TLS server that completes the handshake, reads the request head and writes `response`.
fn tls_server(minted: &Minted, response: Vec<u8>) -> u16 {
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
        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    });
    port
}

/// A TLS signer client trusting the minted CA.
fn tls_signer(m: &Minted, port: u16) -> RemoteSigner {
    let client = Client::connect(
        &format!("https://127.0.0.1:{port}"),
        "u",
        "p",
        Some(&m.ca_pem),
        None,
    )
    .unwrap();
    RemoteSigner::new(client, "btc")
}

#[test]
fn signs_a_psbt_over_verified_tls() {
    let m = mint();
    let psbt = psbt_paying(100_000);
    // The signer returns the same unsigned transaction, "complete".
    let body = ok_body(&format!(r#"{{"psbt":"{psbt}","complete":true}}"#));
    let port = tls_server(&m, body);
    let signed = tls_signer(&m, port).sign(&psbt).expect("signer signs");
    assert_eq!(signed, psbt);
}

#[test]
fn a_typed_refusal_is_surfaced_as_refused() {
    let m = mint();
    let body = http(
        "200 OK",
        r#"{"result":null,"error":{"code":7,"message":"policy: amount exceeds ceiling"},"id":0}"#,
    );
    let port = tls_server(&m, body);
    let err = tls_signer(&m, port)
        .sign(&psbt_paying(100_000))
        .unwrap_err();
    match err {
        NodeError::Signer(SignerError::Refused { code, message }) => {
            assert_eq!(code, 7);
            assert!(message.contains("ceiling"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_incomplete_signature_is_refused() {
    let m = mint();
    let psbt = psbt_paying(100_000);
    let body = ok_body(&format!(r#"{{"psbt":"{psbt}","complete":false}}"#));
    let port = tls_server(&m, body);
    let err = tls_signer(&m, port).sign(&psbt).unwrap_err();
    assert!(matches!(
        err,
        NodeError::Signer(SignerError::Refused { .. })
    ));
}

#[test]
fn a_reply_without_a_psbt_is_malformed() {
    let m = mint();
    let body = ok_body(r#"{"complete":true}"#);
    let port = tls_server(&m, body);
    let err = tls_signer(&m, port)
        .sign(&psbt_paying(100_000))
        .unwrap_err();
    assert!(matches!(err, NodeError::Signer(SignerError::Malformed(_))));
}

#[test]
fn a_swapped_transaction_is_rejected_as_malformed() {
    let m = mint();
    let sent = psbt_paying(100_000);
    // A valid PSBT, but over a different transaction (a different output value, so a different txid).
    let other = psbt_paying(999_999);
    let body = ok_body(&format!(r#"{{"psbt":"{other}","complete":true}}"#));
    let port = tls_server(&m, body);
    let err = tls_signer(&m, port).sign(&sent).unwrap_err();
    match err {
        NodeError::Signer(SignerError::Malformed(msg)) => {
            assert!(msg.contains("different transaction"), "{msg}");
        }
        other => panic!("expected malformed, got {other:?}"),
    }
}

#[test]
fn the_probe_accepts_a_successful_answer() {
    let m = mint();
    let port = tls_server(&m, ok_body(r#"{"version":"mock"}"#));
    tls_signer(&m, port)
        .probe()
        .expect("a conforming signer probes ok");
}

#[test]
fn the_probe_rejects_an_rpc_error() {
    // An endpoint that answers but is not a conforming signer (e.g. a bitcoind node mistakenly
    // configured here) returns a JSON-RPC error; the daemon must refuse to start, not fund hot.
    let m = mint();
    let body = http(
        "200 OK",
        r#"{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":0}"#,
    );
    let port = tls_server(&m, body);
    let err = tls_signer(&m, port).probe().unwrap_err();
    assert!(
        matches!(err, NodeError::Signer(SignerError::Refused { .. })),
        "expected a refusal, got {err:?}"
    );
}

// --- plain-TCP mocks for the timeout and unreachable paths -------------------------------------

/// A one-shot TCP server that accepts, reads the request, then holds the connection without ever
/// replying, so the client's read times out.
fn hang_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut tcp, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            let _ = tcp.read(&mut buf);
            thread::sleep(Duration::from_secs(3));
        }
    });
    port
}

/// A loopback port with nothing listening (bound then dropped), so a connect is refused at once.
fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn a_stalled_signer_times_out() {
    let port = hang_server();
    let client = Client::connect(&format!("http://127.0.0.1:{port}"), "u", "p", None, None)
        .unwrap()
        .with_timeout(Duration::from_secs(1));
    let signer = RemoteSigner::new(client, "btc");
    let start = Instant::now();
    let err = signer.sign(&psbt_paying(100_000)).unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the tight timeout must fire well before the hang server returns"
    );
    assert!(
        matches!(err, NodeError::Signer(SignerError::Timeout)),
        "expected a timeout, got {err:?}"
    );
    // The probe over the same stalled endpoint must also be a timeout, not a false "reachable".
    let probe = RemoteSigner::new(
        Client::connect(&format!("http://127.0.0.1:{port}"), "u", "p", None, None)
            .unwrap()
            .with_timeout(Duration::from_secs(1)),
        "btc",
    )
    .probe();
    assert!(matches!(
        probe,
        Err(NodeError::Signer(SignerError::Timeout))
    ));
}

#[test]
fn an_unreachable_signer_is_refused_with_no_hot_fallback() {
    let port = dead_port();
    let signer = RemoteSigner::new(
        Client::connect(&format!("http://127.0.0.1:{port}"), "u", "p", None, None).unwrap(),
        "btc",
    );
    // The probe the daemon runs before provisioning: a refused connection is Unreachable, so the
    // daemon refuses to start rather than silently funding hot.
    assert!(matches!(
        signer.probe(),
        Err(NodeError::Signer(SignerError::Unreachable(_)))
    ));
    // A sign attempt on the dead endpoint is likewise an error, never a silent success.
    assert!(signer.sign(&psbt_paying(100_000)).is_err());
}

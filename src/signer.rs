//! The remote (cold) funding signer (design 0012): forwards an unsigned, fully described funding
//! PSBT to an external signer over the same transport the node RPC uses (HTTPS verified against a
//! Root CA on the LAN, or a Tor onion through the SOCKS proxy; design 0011), and returns it signed.
//! The signer holds the funding keys; the engine host does not. `RemoteSigner` finalises nothing: it
//! returns the signed PSBT and the engine finalises it through the node, exactly as it does for the
//! hot `WalletSigner`.
//!
//! ## The protocol a reference signer must implement
//!
//! JSON-RPC 1.0 (the same framing as bitcoind), carried over [`crate::rpc::Client`], so the signer
//! reuses the node transport with zero new network code. Two methods:
//!
//! - `signfundingpsbt`, params `[{ "psbt": <base64>, "chain": "btc" | "xbtc" }]`, with result
//!   `{ "psbt": <base64 signed PSBT>, "complete": <bool> }`.
//!   The signer may only ADD signatures: the returned PSBT's unsigned transaction must be identical
//!   to the one sent (same txid). The `chain` tag lets a signer refuse a crossed config, since both
//!   chains report `"main"` and share Bitcoin's address format.
//! - `getsignerinfo`, params `[]` -> any result. Used only as a reachability probe at startup.
//!
//! A refusal is a JSON-RPC error object `{ "code", "message" }` (a policy ceiling, an allow-list, a
//! rate limit, ...). A refusal, a transport failure, a timeout, and a malformed reply are mapped to
//! the distinct [`SignerError`] variants so the daemon never confuses "do not fund" with a success.

use std::str::FromStr;

use bitcoin::Psbt;
use serde_json::{json, Value};

use crate::node::{FundingSigner, NodeError, SignerError};
use crate::rpc::{Client, RpcError};

/// A funding signer that does not sign: it returns the unsigned PSBT as
/// [`NodeError::AwaitingSignature`], for a swap where the user signs in their own wallet (Sparrow for
/// BTC, Shrike for xBTC) and submits the signed PSBT out of band (E2, design 0017). The engine parks
/// the swap on this signal instead of funding; no spending key ever reaches the operator's side.
pub struct InteractiveSigner;

impl FundingSigner for InteractiveSigner {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError> {
        Err(NodeError::AwaitingSignature {
            psbt: unsigned_psbt.to_owned(),
        })
    }
}

/// A funding signer reached over the node transport. `chain` tags each request ("btc" or "xbtc").
pub struct RemoteSigner {
    client: Client,
    chain: &'static str,
}

impl RemoteSigner {
    /// Wraps a transport `client` already pointed at the signer endpoint (built by
    /// `rpc::Client::connect`, so it carries the signer's auth, Root CA and SOCKS proxy). `chain` is
    /// "btc" or "xbtc".
    pub fn new(client: Client, chain: &'static str) -> RemoteSigner {
        RemoteSigner { client, chain }
    }

    /// Probes the signer at startup (design 0012): it must answer `getsignerinfo` successfully. A
    /// transport failure is `Unreachable` or `Timeout`; a JSON-RPC error is a `Refused` (the endpoint
    /// answered but is not a conforming signer, for example a bitcoind node mistakenly configured as
    /// the signer endpoint, since the two share the endpoint shape). Either way the daemon refuses to
    /// start rather than silently funding hot.
    pub fn probe(&self) -> Result<(), NodeError> {
        self.client
            .call("getsignerinfo", json!([]))
            .map(|_| ())
            .map_err(refusal_or_transport)
    }
}

impl FundingSigner for RemoteSigner {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError> {
        let params = json!([{ "psbt": unsigned_psbt, "chain": self.chain }]);
        let reply = self
            .client
            .call("signfundingpsbt", params)
            .map_err(refusal_or_transport)?;
        let signed = reply["psbt"].as_str().ok_or_else(|| {
            NodeError::Signer(SignerError::Malformed("no psbt in the signer reply".into()))
        })?;
        if reply["complete"] != Value::Bool(true) {
            return Err(NodeError::Signer(SignerError::Refused {
                code: 0,
                message: "signer did not fully sign the funding psbt".into(),
            }));
        }
        // The signer may only add signatures; the unsigned transaction it signed must be the one we
        // sent, or it has rewritten the funding (a different destination, amount or input). Reject.
        verify_same_unsigned_tx(unsigned_psbt, signed)?;
        Ok(signed.to_owned())
    }
}

/// An error from the `signfundingpsbt` call: a JSON-RPC error is the signer's typed refusal;
/// anything else is a transport problem.
fn refusal_or_transport(e: RpcError) -> NodeError {
    match e {
        RpcError::Rpc { code, message } => {
            NodeError::Signer(SignerError::Refused { code, message })
        }
        other => transport_error(other),
    }
}

/// Classifies a transport-layer `RpcError` into a [`SignerError`]. A timed-out read, a refused
/// connection and a TLS or HTTP failure all mean the signer is not usable now; none of them fall
/// back to hot.
fn transport_error(e: RpcError) -> NodeError {
    let err = match e {
        RpcError::Io(io) => {
            use std::io::ErrorKind::{TimedOut, WouldBlock};
            if matches!(io.kind(), TimedOut | WouldBlock) {
                SignerError::Timeout
            } else {
                SignerError::Unreachable(io.to_string())
            }
        }
        RpcError::Http(m) | RpcError::Tls(m) | RpcError::Config(m) => SignerError::Unreachable(m),
        RpcError::Json(e) => SignerError::Malformed(e.to_string()),
        RpcError::Rpc { code, message } => SignerError::Refused { code, message },
    };
    NodeError::Signer(err)
}

/// Rejects a signed PSBT whose unsigned transaction differs from the one sent (a different txid).
fn verify_same_unsigned_tx(before: &str, after: &str) -> Result<(), NodeError> {
    let parse = |s: &str| {
        Psbt::from_str(s)
            .map_err(|e| NodeError::Signer(SignerError::Malformed(format!("psbt: {e}"))))
    };
    if parse(before)?.unsigned_tx.compute_txid() != parse(after)?.unsigned_tx.compute_txid() {
        return Err(NodeError::Signer(SignerError::Malformed(
            "signer returned a different transaction than it was asked to sign".into(),
        )));
    }
    Ok(())
}

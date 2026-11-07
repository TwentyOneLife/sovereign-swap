//! A minimal reference cold funding signer (design 0012). Nothing off the shelf speaks the
//! `RemoteSigner` protocol (`src/signer.rs`), so this is the runnable counterpart an operator can
//! deploy: a small service that holds the funding keys and signs funding PSBTs a sovereign-swap
//! daemon in cold mode forwards to it. The daemon's funding wallet is watch-only; this service's
//! wallet is the keyed counterpart.
//!
//! ## What it is, and is not
//!
//! "Cold" here means key-separated, not air-gapped (0008): the engine host never holds the funding
//! keys, so a full compromise of the daemon can only propose funding PSBTs, never move the balance.
//! The signer is the backstop that validates each PSBT and can REFUSE; it never blind-signs. This is
//! form (1) of 0012 (a second key-holding service reached over the node transport), implemented by
//! bridging to a bitcoind wallet that holds the keys and signing with `walletprocesspsbt`.
//!
//! ## The protocol (design 0012, `src/signer.rs`)
//!
//! JSON-RPC 1.0 over HTTP, the same framing bitcoind uses, so the daemon reaches it with `RemoteSigner`
//! over the existing [`crate::rpc::Client`] transport and no new network code. Two methods:
//!
//! - `signfundingpsbt`, params `[{ "psbt": <base64>, "chain": "btc" | "xbtc" }]`, result
//!   `{ "psbt": <base64 signed>, "complete": <bool> }`. The service only ADDS signatures (the client
//!   enforces a same-txid check), and reports `complete` straight from `walletprocesspsbt`.
//! - `getsignerinfo`, params `[]` -> a static info object; the client's reachability probe. It makes
//!   no bitcoind call, so the daemon's startup probe does not depend on the wallet being warm.
//!
//! Every refusal, and every framing error, is a JSON-RPC error object `{ "code", "message" }` so the
//! daemon maps it to [`crate::node::SignerError::Refused`] rather than a silent success.
//!
//! ## Policy (the whole point of key separation)
//!
//! The service refuses before it signs:
//!
//! - **Chain tag.** Both chains report `"main"` and share Bitcoin's address format, so a crossed
//!   config is dangerous. The request's `chain` must equal the one this signer serves, checked before
//!   any bitcoind call.
//! - **Outflow ceiling** (`max_outflow_sats`). The value that LEAVES the wallet in one funding PSBT:
//!   the sum of outputs that are not the wallet's own, plus the miner fee. Change back to the wallet
//!   is excluded (determined by asking the keyed wallet `getaddressinfo().ismine`, never by trusting
//!   the daemon-supplied PSBT derivation fields). Fails closed: a missing input UTXO, an undecodable
//!   output, or outputs exceeding inputs is a refusal, not a sign.
//!
//! An address allow-list is intentionally NOT implemented: a swap's lock output is a fresh per-swap
//! HTLC P2WSH (a new `secret_hash` and keys each time), so a static address allow-list would refuse
//! every real funding. A useful script-level policy would be a template allow-list (assert the lock
//! output is a P2WSH whose `witness_script` is a known HTLC shape); that needs the engine to carry the
//! `witness_script` on the lock output in the PSBT, so it is a follow-up, noted here.
//!
//! ## Running it (operator)
//!
//! Load the keyed funding descriptor into a bitcoind wallet (the keyed counterpart of the daemon's
//! watch-only funding wallet; the two share the same account `xpub`). Point the signer at that wallet
//! and run the `sovereign-swap-signer` binary; see its module doc for the environment variables.
//! Then set the daemon's cold funding config (design 0012 stage 2 package action) `signer_endpoint`
//! to this service, with the auth and, on a LAN, the Root CA. Two deployments match the node
//! transport the daemon already speaks: terminate TLS in front of this plain-HTTP service and expose
//! it as HTTPS to a node Root CA on the LAN (as StartOS fronts bitcoind), or publish it as a Tor
//! onion the daemon dials `http://<onion>` through the SOCKS proxy. Bind loopback either way.
//!
//! Limit: a request is capped at [`crate::daemon::wire`]'s 64 KiB, inherited from the daemon's HTTP
//! reader. A funding PSBT is a few KB; a pathological many-input PSBT carrying `non_witness_utxo`
//! could exceed it and be refused as a framing error. Not a concern for ordinary funding.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Address, Network, Psbt, ScriptBuf};
use serde_json::{json, Value};

use crate::daemon::wire::{constant_time_eq, read_request, reason};
use crate::rpc::{base64, Client};

// JSON-RPC 2.0 reserved codes, reused for framing problems so a malformed call is still a typed error.
const E_PARSE: i64 = -32700;
const E_INVALID_REQUEST: i64 = -32600;
const E_METHOD_NOT_FOUND: i64 = -32601;
const E_INVALID_PARAMS: i64 = -32602;
// Application (refusal) codes, positive like bitcoind's own, so the daemon surfaces a `Refused`.
const E_WRONG_CHAIN: i64 = 1;
const E_POLICY_CEILING: i64 = 2;
const E_POLICY_UNDECIDABLE: i64 = 3;
const E_SIGN_FAILED: i64 = 4;

/// The policy the signer enforces before it will sign. A key-separated signer exists to validate and
/// be able to refuse; expand this as stronger controls land (see the module doc on the allow-list).
pub struct SignerPolicy {
    /// The most value (sats) allowed to LEAVE the wallet in one funding PSBT: outputs that are not the
    /// wallet's own, plus the miner fee. `None` means no ceiling (test and regtest convenience only).
    pub max_outflow_sats: Option<u64>,
}

/// Static configuration for the service. The keyed wallet is passed separately to `new`.
pub struct SignerConfig {
    /// The chain this signer serves, `"btc"` or `"xbtc"`. A request tagged otherwise is refused.
    pub chain: String,
    /// HTTP Basic credentials the daemon must present (its `RemoteSigner` transport sends Basic auth,
    /// exactly like a bitcoind RPC client). Compared in constant time.
    pub auth_user: String,
    pub auth_pass: String,
    /// The network the keyed wallet is on, used to turn an output script into an address for the
    /// `ismine` change check. Both chains share Bitcoin's parameters, so this is `Bitcoin` in
    /// production and `Regtest` in the tests.
    pub network: Network,
    pub policy: SignerPolicy,
}

/// The reference signer: a keyed bitcoind wallet behind the design-0012 protocol and a refusal policy.
pub struct SignerService {
    /// A [`crate::rpc::Client`] already pointed at the KEYED wallet (`client.wallet(name)`), i.e. the
    /// counterpart of the daemon's watch-only funding wallet. It holds the private keys and signs.
    wallet: Client,
    cfg: SignerConfig,
}

impl SignerService {
    pub fn new(wallet: Client, cfg: SignerConfig) -> SignerService {
        SignerService { wallet, cfg }
    }

    /// A startup check against the keyed wallet, run before serving: the auth credentials must be
    /// set, and the wallet must actually hold private keys. A wallet with `private_keys_enabled=false`
    /// means the operator pointed the signer at the watch-only funding wallet by mistake, so it could
    /// never sign; refuse to start rather than fail every request later.
    pub fn preflight(&self) -> Result<(), String> {
        if self.cfg.auth_user.is_empty() || self.cfg.auth_pass.is_empty() {
            return Err("signer auth credentials (user and password) must be set".to_owned());
        }
        if !matches!(self.cfg.chain.as_str(), "btc" | "xbtc") {
            return Err(format!(
                "signer chain must be btc or xbtc, got {:?}",
                self.cfg.chain
            ));
        }
        let info = self
            .wallet
            .call("getwalletinfo", json!([]))
            .map_err(|e| format!("getwalletinfo on the signer wallet failed: {e:?}"))?;
        if info["private_keys_enabled"].as_bool() != Some(true) {
            return Err(
                "the signer wallet holds no private keys (pointed at the watch-only funding wallet?)"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// Dispatches one JSON-RPC method. An `Err` is a typed refusal the caller turns into a JSON-RPC
    /// error object.
    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "getsignerinfo" => Ok(self.signer_info()),
            "signfundingpsbt" => self.sign_funding(params),
            other => Err((E_METHOD_NOT_FOUND, format!("unknown method: {other}"))),
        }
    }

    /// A static reachability answer; deliberately makes no bitcoind call.
    fn signer_info(&self) -> Value {
        json!({
            "service": "sovereign-swap reference signer",
            "version": env!("CARGO_PKG_VERSION"),
            "chain": self.cfg.chain,
            "ceiling_sat": self.cfg.policy.max_outflow_sats,
        })
    }

    /// Validates, then signs: chain tag, then the outflow ceiling, then `walletprocesspsbt` on the
    /// keyed wallet. The signer adds signatures only; `walletprocesspsbt` never rewrites the unsigned
    /// transaction, so the client's same-txid check always holds.
    fn sign_funding(&self, params: &Value) -> Result<Value, (i64, String)> {
        let obj = params.get(0).ok_or((
            E_INVALID_PARAMS,
            "params: expected [{psbt, chain}]".to_owned(),
        ))?;
        let psbt_b64 = obj["psbt"]
            .as_str()
            .ok_or((E_INVALID_PARAMS, "missing \"psbt\"".to_owned()))?;
        let chain = obj["chain"]
            .as_str()
            .ok_or((E_INVALID_PARAMS, "missing \"chain\"".to_owned()))?;

        // Chain tag first, before any bitcoind call: a crossed config (btc funding reaching an xbtc
        // signer or the reverse) is refused outright, since both chains share Bitcoin's address format.
        if chain != self.cfg.chain {
            return Err((
                E_WRONG_CHAIN,
                format!(
                    "this signer serves {}, but the request is tagged {chain}",
                    self.cfg.chain
                ),
            ));
        }

        let psbt = Psbt::from_str(psbt_b64)
            .map_err(|e| (E_INVALID_PARAMS, format!("could not parse the psbt: {e}")))?;

        if let Some(max) = self.cfg.policy.max_outflow_sats {
            let outflow = compute_outflow_sats(&psbt, |spk| self.output_is_mine(spk))
                .map_err(|m| (E_POLICY_UNDECIDABLE, m))?;
            if outflow > max {
                return Err((
                    E_POLICY_CEILING,
                    format!(
                        "policy: funding outflow {outflow} sat exceeds the ceiling of {max} sat"
                    ),
                ));
            }
        }

        let signed = self
            .wallet
            .call("walletprocesspsbt", json!([psbt_b64]))
            .map_err(|e| (E_SIGN_FAILED, format!("walletprocesspsbt failed: {e:?}")))?;
        let out_psbt = signed["psbt"].as_str().ok_or((
            E_SIGN_FAILED,
            "no psbt in the walletprocesspsbt reply".to_owned(),
        ))?;
        let complete = signed["complete"].as_bool().unwrap_or(false);
        Ok(json!({ "psbt": out_psbt, "complete": complete }))
    }

    /// Whether an output script pays back to the keyed wallet (change), decided by the wallet itself.
    /// The daemon-supplied PSBT derivation fields are never trusted for this; a compromised daemon
    /// could forge them to dodge the ceiling. Fails closed: a non-address script is "not ours".
    fn output_is_mine(&self, spk: &ScriptBuf) -> Result<bool, String> {
        let addr = Address::from_script(spk, self.cfg.network)
            .map_err(|_| "a funding output is not a standard address; refusing".to_owned())?;
        let info = self
            .wallet
            .call("getaddressinfo", json!([addr.to_string()]))
            .map_err(|e| format!("getaddressinfo failed: {e:?}"))?;
        Ok(info["ismine"].as_bool().unwrap_or(false))
    }

    // --- HTTP serving (reuses the daemon's request reader and auth primitive) -------------------

    /// Bound on concurrent connections, so a flood cannot exhaust threads. The signer serves one
    /// local daemon, so this is generous; it mirrors the daemon's and relay's own guard.
    const MAX_CONNECTIONS: usize = 64;

    /// Binds and serves forever on `bind`. A thread per connection.
    pub fn serve(self, bind: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind)?;
        self.accept_loop(listener);
        Ok(())
    }

    /// Binds `bind` (use `127.0.0.1:0` for an ephemeral port) and serves in a background thread.
    /// Returns the bound address. For tests and for a supervisor that wants the resolved port.
    pub fn spawn(self, bind: &str) -> std::io::Result<String> {
        let listener = TcpListener::bind(bind)?;
        let addr = listener.local_addr()?.to_string();
        std::thread::spawn(move || self.accept_loop(listener));
        Ok(addr)
    }

    fn accept_loop(self, listener: TcpListener) {
        let me = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming().flatten() {
            if active.load(Ordering::Relaxed) >= Self::MAX_CONNECTIONS {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                continue;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let me = Arc::clone(&me);
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                me.serve_connection(stream);
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    fn serve_connection(&self, mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let req = match read_request(&mut stream) {
            Ok(req) => req,
            // A framing error is still a JSON-RPC error object (HTTP 200), never a bare status, so the
            // daemon reads a message instead of a confusing empty refusal.
            Err(code) => {
                let msg = match code {
                    413 => "request too large",
                    _ => "malformed http request",
                };
                return self.write_rpc(
                    &mut stream,
                    200,
                    Value::Null,
                    Err((E_INVALID_REQUEST, msg.to_owned())),
                );
            }
        };
        // HTTP Basic auth, constant-time, exactly as the daemon checks its web password. A failure is
        // HTTP 401 (which the client maps to Unreachable), so a wrong credential refuses to fund.
        if !self.authorized(&req.headers) {
            return self.write_rpc(
                &mut stream,
                401,
                Value::Null,
                Err((E_INVALID_REQUEST, "unauthorized".to_owned())),
            );
        }
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => {
                return self.write_rpc(
                    &mut stream,
                    200,
                    Value::Null,
                    Err((E_PARSE, "request body is not valid json".to_owned())),
                )
            }
        };
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let method = body["method"].as_str().unwrap_or("");
        let params = body.get("params").cloned().unwrap_or_else(|| json!([]));
        let result = self.dispatch(method, &params);
        self.write_rpc(&mut stream, 200, id, result);
    }

    fn authorized(&self, headers: &std::collections::BTreeMap<String, String>) -> bool {
        match headers.get("authorization") {
            Some(h) => {
                let expected = format!(
                    "Basic {}",
                    base64(format!("{}:{}", self.cfg.auth_user, self.cfg.auth_pass).as_bytes())
                );
                constant_time_eq(h.as_bytes(), expected.as_bytes())
            }
            None => false,
        }
    }

    /// Writes one JSON-RPC 1.0 response body (bitcoind's shape): `result` set and `error` null on
    /// success, or `result` null and `error` the `{code, message}` object on a refusal.
    fn write_rpc(
        &self,
        stream: &mut TcpStream,
        status: u16,
        id: Value,
        result: Result<Value, (i64, String)>,
    ) {
        let body = match result {
            Ok(v) => json!({ "result": v, "error": Value::Null, "id": id }),
            Err((code, message)) => {
                json!({ "result": Value::Null, "error": { "code": code, "message": message }, "id": id })
            }
        };
        let body = body.to_string();
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\
             Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
            reason = reason(status),
            len = body.len(),
        );
        let _ = stream.write_all(resp.as_bytes());
    }
}

/// The value (sats) leaving the wallet in a funding PSBT: every output that is not the wallet's own,
/// plus the miner fee. `is_mine` decides ownership per output script (the service asks the keyed
/// wallet; a test passes a closure). Fails closed: a missing input UTXO, an arithmetic overflow, or
/// outputs exceeding inputs returns an error so the caller refuses rather than signs.
pub(crate) fn compute_outflow_sats<F>(psbt: &Psbt, mut is_mine: F) -> Result<u64, String>
where
    F: FnMut(&ScriptBuf) -> Result<bool, String>,
{
    let mut total_in: u64 = 0;
    for (i, input) in psbt.inputs.iter().enumerate() {
        let value = if let Some(utxo) = &input.witness_utxo {
            utxo.value.to_sat()
        } else if let Some(tx) = &input.non_witness_utxo {
            let vout = psbt
                .unsigned_tx
                .input
                .get(i)
                .ok_or_else(|| "psbt input index out of range".to_owned())?
                .previous_output
                .vout as usize;
            tx.output
                .get(vout)
                .ok_or_else(|| "psbt non_witness_utxo lacks the spent output".to_owned())?
                .value
                .to_sat()
        } else {
            return Err("a psbt input carries no utxo; cannot bound the outflow".to_owned());
        };
        total_in = total_in
            .checked_add(value)
            .ok_or_else(|| "input amount overflow".to_owned())?;
    }

    let mut total_out: u64 = 0;
    let mut leaving: u64 = 0;
    for txout in &psbt.unsigned_tx.output {
        let value = txout.value.to_sat();
        total_out = total_out
            .checked_add(value)
            .ok_or_else(|| "output amount overflow".to_owned())?;
        if !is_mine(&txout.script_pubkey)? {
            leaving = leaving
                .checked_add(value)
                .ok_or_else(|| "outflow amount overflow".to_owned())?;
        }
    }

    let fee = total_in
        .checked_sub(total_out)
        .ok_or_else(|| "psbt outputs exceed its inputs".to_owned())?;
    leaving
        .checked_add(fee)
        .ok_or_else(|| "outflow amount overflow".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    /// A PSBT spending one `input_sats` input into outputs of `out_sats`, with each output's
    /// ownership flagged by `mine`. The miner fee is `input_sats - sum(out_sats)`.
    fn psbt(input_sats: u64, outs: &[(u64, bool)]) -> (Psbt, Vec<bool>) {
        let output = outs
            .iter()
            .enumerate()
            .map(|(i, (sats, _))| TxOut {
                value: Amount::from_sat(*sats),
                // A distinct, non-empty script per output so `is_mine` can key off it.
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, i as u8]),
            })
            .collect();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output,
        };
        let mut p = Psbt::from_unsigned_tx(tx).unwrap();
        p.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: ScriptBuf::new(),
        });
        (p, outs.iter().map(|(_, m)| *m).collect())
    }

    fn mine_for<'a>(
        p: &'a Psbt,
        mine: &'a [bool],
    ) -> impl FnMut(&ScriptBuf) -> Result<bool, String> + 'a {
        move |spk: &ScriptBuf| {
            let idx = p
                .unsigned_tx
                .output
                .iter()
                .position(|o| &o.script_pubkey == spk)
                .unwrap();
            Ok(mine[idx])
        }
    }

    #[test]
    fn outflow_excludes_change_and_includes_the_fee() {
        // 1_000_000 in -> 500_000 lock (not ours) + 499_000 change (ours); fee 1_000.
        let (p, mine) = psbt(1_000_000, &[(500_000, false), (499_000, true)]);
        let out = compute_outflow_sats(&p, mine_for(&p, &mine)).unwrap();
        // 500_000 (leaves) + 1_000 (fee) = 501_000; the 499_000 change is excluded.
        assert_eq!(out, 501_000);
    }

    #[test]
    fn outflow_of_an_all_change_psbt_is_just_the_fee() {
        let (p, mine) = psbt(1_000_000, &[(999_500, true)]);
        assert_eq!(compute_outflow_sats(&p, mine_for(&p, &mine)).unwrap(), 500);
    }

    #[test]
    fn a_psbt_input_without_a_utxo_fails_closed() {
        let (mut p, mine) = psbt(1_000_000, &[(500_000, false)]);
        p.inputs[0].witness_utxo = None;
        assert!(compute_outflow_sats(&p, mine_for(&p, &mine)).is_err());
    }

    #[test]
    fn outputs_exceeding_inputs_fail_closed() {
        let (p, mine) = psbt(100, &[(500_000, false)]);
        assert!(compute_outflow_sats(&p, mine_for(&p, &mine)).is_err());
    }
}

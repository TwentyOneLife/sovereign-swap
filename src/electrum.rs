//! Electrum protocol client for the E1 `ChainBackend` (design 0016). A line-delimited JSON-RPC client
//! over TCP, optionally through a SOCKS5 proxy for a Tor onion, mirroring `rpc.rs`'s transport. The
//! `ElectrumBackend` that implements `ChainBackend` on top of this client lands next (see 0016); this
//! module is the self-contained, unit-testable core: the client and the `scripthash` primitive.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::ScriptBuf;
use serde_json::{json, Value};

use crate::node::NodeError;
use crate::socks::socks5_connect;

/// Budget for opening the socket (direct connect, or the whole SOCKS handshake).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for one request/response.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The Electrum `scripthash` for a scriptPubKey: `SHA-256(scriptPubKey)`, byte-reversed, lower hex.
/// Every `blockchain.scripthash.*` query addresses a contract's output script by this value.
pub fn scripthash(script: &ScriptBuf) -> String {
    let mut bytes = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    bytes.reverse();
    bytes[..].to_lower_hex_string()
}

/// A minimal Electrum (ElectrumX / Fulcrum / Shulcrum) JSON-RPC client over a single socket. One call
/// writes one line and reads one line; a `Mutex` serialises calls so the id/response stay paired.
pub struct ElectrumClient {
    stream: Mutex<BufReader<TcpStream>>,
    next_id: AtomicU64,
}

impl ElectrumClient {
    /// Connects to `host:port` directly, or through `socks` (a SOCKS5 proxy, as a Tor onion needs).
    /// Plain TCP, framed by newlines; TLS for a clearnet LAN server is a later step (design 0016).
    pub fn connect(host: &str, port: u16, socks: Option<&str>) -> Result<Self, NodeError> {
        let stream = match socks {
            Some(proxy) => socks5_connect(proxy, host, port, CONNECT_TIMEOUT)
                .map_err(|e| NodeError::Unexpected(format!("electrum socks connect: {e}")))?,
            None => {
                let addr = (host, port)
                    .to_socket_addrs()
                    .map_err(|e| NodeError::Unexpected(format!("electrum address: {e}")))?
                    .next()
                    .ok_or_else(|| NodeError::Unexpected("electrum: no address resolved".into()))?;
                TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
                    .map_err(|e| NodeError::Unexpected(format!("electrum connect: {e}")))?
            }
        };
        stream
            .set_read_timeout(Some(CALL_TIMEOUT))
            .map_err(|e| NodeError::Unexpected(e.to_string()))?;
        Ok(Self {
            stream: Mutex::new(BufReader::new(stream)),
            next_id: AtomicU64::new(1),
        })
    }

    /// One JSON-RPC call: write a single request line, read one response line. A JSON-RPC `error`
    /// field is the server's typed refusal; anything else is returned as the `result`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, NodeError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = json!({"id": id, "method": method, "params": params}).to_string();
        line.push('\n');
        let mut guard = self.stream.lock().expect("electrum lock");
        guard
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(|e| NodeError::Unexpected(format!("electrum write: {e}")))?;
        let mut resp = String::new();
        let read = guard
            .read_line(&mut resp)
            .map_err(|e| NodeError::Unexpected(format!("electrum read: {e}")))?;
        if read == 0 {
            return Err(NodeError::Unexpected("electrum: connection closed".into()));
        }
        let v: Value = serde_json::from_str(resp.trim())
            .map_err(|e| NodeError::Unexpected(format!("electrum parse: {e}")))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(NodeError::Unexpected(format!("electrum {method}: {err}")));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hex::FromHex;

    #[test]
    fn scripthash_matches_the_electrum_reference_vector() {
        // Electrum protocol docs: the P2PKH scriptPubKey for 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH.
        let spk =
            ScriptBuf::from_hex("76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac").unwrap();
        assert_eq!(
            scripthash(&spk),
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        );
    }

    #[test]
    fn scripthash_is_reversed_not_raw_sha256() {
        let spk = ScriptBuf::from_hex("0014000102030405060708090a0b0c0d0e0f1011121314").unwrap();
        let raw = sha256::Hash::hash(spk.as_bytes()).to_byte_array()[..].to_lower_hex_string();
        assert_ne!(
            scripthash(&spk),
            raw,
            "scripthash must be byte-reversed, not raw sha256"
        );
    }
}

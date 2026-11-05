//! Minimal JSON-RPC client for a local bitcoind (Core or Knots), over plain HTTP.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use bitcoin::OutPoint;
use serde_json::{json, Value};

use crate::replay::UtxoLookup;

#[derive(Debug)]
pub enum RpcError {
    Io(std::io::Error),
    Http(String),
    Json(serde_json::Error),
    Rpc { code: i64, message: String },
}

#[derive(Clone, Debug)]
pub struct Client {
    host_port: String,
    path: String,
    authorization: String,
}

impl Client {
    pub fn new(host_port: &str, user: &str, password: &str) -> Client {
        Client {
            host_port: host_port.to_owned(),
            path: "/".to_owned(),
            authorization: base64(format!("{user}:{password}").as_bytes()),
        }
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
        let mut stream = TcpStream::connect(&self.host_port).map_err(RpcError::Io)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(RpcError::Io)?;
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.path, self.host_port, self.authorization, body.len(), body
        )
        .map_err(RpcError::Io)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(RpcError::Io)?;
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| RpcError::Http("no header end".into()))?;
        let payload = &response[split + 4..];
        if payload.is_empty() {
            let status = String::from_utf8_lossy(&response[..split]);
            return Err(RpcError::Http(
                status.lines().next().unwrap_or_default().to_owned(),
            ));
        }
        let mut reply: Value = serde_json::from_slice(payload).map_err(RpcError::Json)?;
        if let Some(err) = reply.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Rpc {
                code: err["code"].as_i64().unwrap_or_default(),
                message: err["message"].as_str().unwrap_or_default().to_owned(),
            });
        }
        Ok(reply["result"].take())
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

fn base64(input: &[u8]) -> String {
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
}

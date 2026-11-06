//! SOCKS5 CONNECT, no authentication, address type "domain" (socks5h): the proxy resolves the host
//! name, so an `.onion` is dialed inside the Tor circuit and no name ever leaks to a local resolver.
//! Shared by the Nostr relay transport (design 0006) and the node RPC transport (design 0011).

use std::io::{Error, Read, Result, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Dials `host:port` through the SOCKS5 proxy at `proxy`. The host is sent to the proxy verbatim, so
/// an `.onion` is resolved and reached by Tor, not locally. `timeout` bounds the proxy connect and
/// every step of the handshake: a stalled Tor circuit must fail, never hang the caller forever (a
/// hung engine thread would miss a refund, design 0011).
pub fn socks5_connect(proxy: &str, host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr = proxy
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| fail("SOCKS proxy address did not resolve"))?;
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    // Greeting: version 5, one method, no authentication.
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply != [0x05, 0x00] {
        return Err(fail("proxy rejected no-auth"));
    }
    // CONNECT, address type domain (0x03): remote resolution.
    let host = host.as_bytes();
    if host.len() > 255 {
        return Err(fail("host too long for SOCKS5 domain address"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    // Reply: version, status, reserved, then a bound address we read and discard.
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(fail(&format!("SOCKS5 CONNECT failed, status {}", head[1])));
    }
    let bound = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        _ => return Err(fail("unknown SOCKS5 bound address type")),
    };
    let mut discard = vec![0u8; bound];
    s.read_exact(&mut discard)?;
    Ok(s)
}

fn fail(message: &str) -> Error {
    Error::other(message.to_owned())
}

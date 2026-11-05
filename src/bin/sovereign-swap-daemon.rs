//! Runs the sovereign-swap client daemon (design 0009). Loopback-only API by default; the token is
//! written to the data dir on first run. Config: SWAP_DATA_DIR (default ~/.sovereign-swap),
//! SWAP_API_BIND (default 127.0.0.1:8787), SWAP_API_TRUST_NETWORK=1 to permit a non-loopback bind.
use std::path::Path;

use sovereign_swap::daemon::Daemon;

fn main() -> std::io::Result<()> {
    let data_dir = std::env::var("SWAP_DATA_DIR").unwrap_or_else(|_| {
        format!(
            "{}/.sovereign-swap",
            std::env::var("HOME").unwrap_or_else(|_| ".".to_owned())
        )
    });
    let bind = std::env::var("SWAP_API_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    // The API touches funds and must never be reachable off the machine by accident. Refuse a
    // non-loopback bind unless SWAP_API_TRUST_NETWORK=1 is set explicitly: that is for a sandbox that
    // provides its own boundary, e.g. a StartOS service exposed only through an authenticated Tor
    // onion, where the daemon binds the service bridge and StartOS plus the API token are the gate.
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(&bind);
    let loopback = host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
    let trust_network = std::env::var("SWAP_API_TRUST_NETWORK").as_deref() == Ok("1");
    if !loopback && !trust_network {
        eprintln!("refusing to bind {bind}: the daemon API is loopback-only (set SWAP_API_TRUST_NETWORK=1 only behind an authenticated boundary)");
        std::process::exit(1);
    }
    let daemon = Daemon::open(Path::new(&data_dir))?;
    eprintln!("sovereign-swap-daemon: {bind}  (token in {data_dir}/token)");
    daemon.serve(&bind)
}

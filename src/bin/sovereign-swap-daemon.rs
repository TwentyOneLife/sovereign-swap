//! Runs the sovereign-swap client daemon (design 0009). Loopback-only API; the token is written to
//! the data dir on first run. Config: SWAP_DATA_DIR (default ~/.sovereign-swap), SWAP_API_BIND
//! (default 127.0.0.1:8787).
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
    // The API touches funds and must never be reachable off the machine. Refuse a non-loopback bind.
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(&bind);
    if !(host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]") {
        eprintln!("refusing to bind {bind}: the daemon API is loopback-only");
        std::process::exit(1);
    }
    let daemon = Daemon::open(Path::new(&data_dir))?;
    eprintln!("sovereign-swap-daemon: {bind}  (token in {data_dir}/token)");
    daemon.serve(&bind)
}

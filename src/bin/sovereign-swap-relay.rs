//! The `sovereign-swap-relay` binary: a hardened Nostr relay for swap messages.
//!
//! Configuration is read from the environment so no address or operational value lives in the
//! source. Defaults are safe for local use; an operator sets `RELAY_BIND` and the limits.

use sovereign_swap::relay_server::{RelayConfig, RelayServer};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A boolean env flag: on for `1`/`true`/`on`/`yes` (any case), off otherwise or when unset.
fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "on" | "yes"
        ),
        Err(_) => default,
    }
}

fn main() -> std::io::Result<()> {
    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:7777".to_owned());
    let mut cfg = RelayConfig::default();
    cfg.max_event_bytes = env_usize("RELAY_MAX_EVENT_BYTES", cfg.max_event_bytes);
    cfg.max_connections = env_usize("RELAY_MAX_CONNECTIONS", cfg.max_connections);
    cfg.max_events_per_min =
        env_usize("RELAY_MAX_EVENTS_PER_MIN", cfg.max_events_per_min as usize) as u32;
    cfg.max_reqs_per_min =
        env_usize("RELAY_MAX_REQS_PER_MIN", cfg.max_reqs_per_min as usize) as u32;
    cfg.max_req_events = env_usize("RELAY_MAX_REQ_EVENTS", cfg.max_req_events);
    cfg.max_subscriptions = env_usize("RELAY_MAX_SUBSCRIPTIONS", cfg.max_subscriptions);
    cfg.store_cap = env_usize("RELAY_STORE_CAP", cfg.store_cap);
    cfg.retention_secs = env_usize("RELAY_RETENTION_SECS", cfg.retention_secs as usize) as u64;
    cfg.price_proxy = env_bool("RELAY_PRICE_PROXY", cfg.price_proxy);
    eprintln!(
        "sovereign-swap-relay on {bind}: kinds {:?}, max event {} B, {} conns, {}/min, price proxy {}",
        cfg.allowed_kinds,
        cfg.max_event_bytes,
        cfg.max_connections,
        cfg.max_events_per_min,
        if cfg.price_proxy { "on" } else { "off" }
    );
    RelayServer::new(cfg).serve(&bind)
}

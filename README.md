# sovereign-swap

Peer-to-peer atomic swaps between BTC and xBTC (Bitcoin Blake2b, the BLAKE2b proof-of-work hard fork
of Bitcoin). Each party keeps its own keys and runs its own nodes; nobody, including any relay
operator, ever holds the other side's coins.

**Status: early development, not for use with real funds.** What exists today: the on-chain
contract library, the replay guard, and a swap engine (state machine, crash-safe persistence,
funding through the user's own node wallets) that completes swaps between two engines on Bitcoin
Core and Bitcoin Knots BLAKE2b regtest. Messages still travel in memory; the Nostr transport with
post-quantum encryption is the next step.

xBTC and BTC share the address format. Coins sent to an address on the wrong chain are a different
asset. The ticker "xBTC" is also used by unrelated tokens.

## Design

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): the component and data-flow diagrams (message
  plane over Nostr, settlement plane on the two chains).

- [`docs/design/0001-htlc-and-replay-guard.md`](docs/design/0001-htlc-and-replay-guard.md): the
  contract, why it checks the secret's size, and why BTC transactions must not be replayable on xBTC.
- [`docs/design/0002-swap-engine.md`](docs/design/0002-swap-engine.md): the state machine, the
  swap wallet and persistence.
- [`docs/guides/separating-coins.md`](docs/guides/separating-coins.md): separating BTC and xBTC
  coins by hand, step by step.
- [`docs/edge-cases.md`](docs/edge-cases.md): every failure scenario taken over from BasicSwap, with
  the test that covers it.

## Running a relay

`sovereign-swap-relay` is a hardened Nostr relay that carries only swap events (kind 4859): it
verifies every event, serves one kind, caps event size, rate-limits per connection, and bounds its
store with a time-to-live. Run it with `cargo run --bin sovereign-swap-relay`; configure it from the
environment (`RELAY_BIND`, `RELAY_MAX_EVENT_BYTES`, `RELAY_MAX_CONNECTIONS`, `RELAY_MAX_EVENTS_PER_MIN`,
`RELAY_STORE_CAP`, `RELAY_RETENTION_SECS`). Anyone can run one; clients list several.

## Tests

```
scripts/test-in-container.sh                          # unit tests only
scripts/fetch-nodes.sh /tmp/nodes > /tmp/nodes.env    # Bitcoin Core 31.1, Knots BLAKE2b 29.4.3
set -a; . /tmp/nodes.env; set +a
scripts/test-in-container.sh                          # plus regtest against both nodes
```
`fetch-nodes.sh` refuses a release unless its hash matches the pin and its checksums carry a valid
signature from the publisher's key in `keys/`. The build runs in a Rust image pinned by digest, with
`Cargo.lock`.

## Credits

The contract template and the list of edge cases come from
[BasicSwap](https://github.com/basicswap/basicswap) (MIT), which has run secret-hash swaps between
Bitcoin-family chains since 2020. This project is a separate implementation, not a fork.

## License

Dual-licensed. For everyone: **GNU Affero General Public License v3.0 or later** (see `LICENSE`).
Anyone who runs a modified version as a network service has to publish their changes, so improvements
to a swap relay or engine stay open, and self-hosting is always free. For organisations that need
proprietary terms (a closed product, an unattributed service, or removing the default voluntary fee),
a **commercial license** is available, see [`COMMERCIAL.md`](COMMERCIAL.md). Contributions are under
the CLA in [`CLA.md`](CLA.md), which is what lets the project be offered under both.

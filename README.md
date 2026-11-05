# sovereign-swap

Peer-to-peer atomic swaps between BTC and xBTC (Bitcoin Blake2b, the BLAKE2b proof-of-work hard fork
of Bitcoin). Each party keeps its own keys and runs its own nodes; nobody, including any relay
operator, ever holds the other side's coins.

**Status: early development, not for use with real funds.** What exists today is the on-chain
contract library and the replay guard, tested against Bitcoin Core and Bitcoin Knots BLAKE2b on
regtest. No swap engine, wallet or messaging yet.

xBTC and BTC share the address format. Coins sent to an address on the wrong chain are a different
asset. The ticker "xBTC" is also used by unrelated tokens.

## Design

- [`docs/design/0001-htlc-and-replay-guard.md`](docs/design/0001-htlc-and-replay-guard.md): the
  contract, why it checks the secret's size, and why BTC transactions must not be replayable on xBTC.
- [`docs/edge-cases.md`](docs/edge-cases.md): every failure scenario taken over from BasicSwap, with
  the test that covers it.

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

GNU Affero General Public License v3.0 or later, see `LICENSE`. Anyone who runs a modified version as
a network service has to publish their changes, so improvements to a swap relay or engine stay open.

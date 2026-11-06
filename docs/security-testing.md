# Security and test report

What has been tested, how, and the result. Infra-free: deployment-specific results (addresses, onions,
live node checks) live in the operator's private infra notes, not here. Dates: the security/hardening
pass of 2026-11-06.

## 1. Automated test suite (CI-gated, all green)

Every push runs `cargo fmt --check`, `cargo clippy -D warnings`, and the full test suite on the pinned
toolchain. The suite:

- **Unit tests** across the crate (base64, endpoint parsing, fee math, transport rules, settings
  validation, ...).
- **Correctness gated by official vectors**, not hand-rolled expectations:
  - BIP352 silent payments: `silentpayments_vectors.rs` (the BIP's send/receive vectors).
  - BIP374 DLEQ: `dleq_vectors.rs` (the BIP's CSV vectors, including the INVALID cases).
- **End-to-end swap, two parties, in process** (`swap.rs`): maker-sells-BTC and maker-sells-xBTC
  complete; a swap survives a restart after every step; a swap completes after the claim is reorged
  out or the first claim is dropped; the fee path completes end to end.
- **Adversarial tests** (design 0003): a maker refunds when the taker never locks; a taker does not
  lock against a short maker lock, and vice versa; both refund when the maker never claims; the engine
  refuses to lock coins spendable on both chains; a hostile relay cannot break the client
  (`ws_hostile.rs`); duplicate messages do not create duplicate swaps.
- **PRNG hostile-input fuzzing** of the HTLC/contract parsers (`fuzz_parsers.rs`): a counterparty
  controls the contract-script and witness bytes, and these parsers must never panic, loop, or accept
  a non-round-tripping input.
- **Transport**: `rpc_transport.rs` (HTTPS against a Root CA, a wrong CA rejected, chunked and non-200
  JSON bodies, a TLS close without `close_notify`, SOCKS5 remote-DNS dialing, and the
  https-onion-over-SOCKS path) and the ws relay routing tests.

## 2. Coverage-guided fuzzing (cargo-fuzz)

A `fuzz/` workspace with libFuzzer targets on the two riskiest untrusted-input parsers. Both ran clean:

| Target | What it fuzzes | Runs | Result |
|---|---|---|---|
| `http_request` | the daemon HTTP request reader (fully untrusted client bytes from the onion) | ~1.8M in 30s | **0 crashes** |
| `swap_message` | the swap wire-message deserializer (`serde_json` -> `Message`, untrusted peer bytes) | ~12.9M in 30s | **0 crashes** |

`read_request` was made generic over `Read` so a fuzzer can drive it; the parser stays crate-private,
exposed to the fuzz crate only under a `fuzzing` feature. **Next:** wire these into CI as a short soak,
add targets for the Nostr event parser, the PQ envelope open, bech32m address decode, and the DLEQ
verify.

## 3. Denial of service / resilience

- **Finding:** the daemon API accept loop spawned an unbounded thread per connection, with no cap, so a
  slowloris-style flood (over the onion every connection arrives from the Tor proxy, so per-client
  limiting is impossible) could exhaust threads and memory, before auth. The Nostr relay server already
  had `max_connections` + an events-per-minute rate limit; the API did not.
- **Fix:** a connection cap (128) that closes connections over the limit without spawning a thread.
  `daemon_dos.rs` floods past the cap and asserts the daemon stays bounded.
- Done responsibly: demonstrated and fixed against a local instance, not by flooding the production
  node (real-value downtime is not hardening).

## 4. Web UI authentication and config lock

- **Finding:** the web UI served the page (and the API token embedded in it) with no auth, so knowing
  the onion was enough to drive the swaps.
- **Fix:** HTTP Basic auth on the page and its assets, with a password generated randomly per install
  (StartOS package) and changeable by the operator; the token is never served without the password, so
  the whole UI is behind it. Constant-time credential comparison. `SWAP_CONFIG_LOCKED` makes node/relay
  config read-only in the page (`PUT /settings` -> 403), leaving the package action the single config
  source.
- **Verified live** (through the deployed daemon): the page with no credentials returns `401` with
  `WWW-Authenticate: Basic`; with the generated password returns `200`; `PUT /settings` returns `403`;
  the API with no token returns `401`.

## 5. Malicious-counterparty harness

`malicious_counterparty.rs` adds a `Tamper` transport: a composable malicious peer that rewrites what a
counterparty sends (duplicate, drop everything, drop selectively, substitute, inject). Message-order and
-count attacks that the byte-level fuzzers do not reach. Three self-tests cover the primitive; it is
designed to be driven against the two-party regtest harness and extended with new attacks during live
real-funds testing (lock-and-vanish, replayed `Accept`, mismatched `secret_hash`, `FeeProof` floods,
`Bid` for a non-existent offer, racing `Accept`s).

## 6. Live deployment verification

Verified end to end on the operator's StartOS node (details in the private infra notes):

- The client reaches both nodes over verified HTTPS (Root CA) and the relay over Tor; `getblockcount`,
  wallet creation, and an authenticated RPC round trip all succeed.
- The engine starts (`/status` reports it), with node and relay connectivity true.
- The web UI auth and config lock behave as in section 4.
- Swap-lifecycle logging now records a new swap and every phase transition to the service log, so a swap
  can be followed in `package logs`, not only the web UI (added for operator monitoring; no secrets are
  logged).

## 7. Kali toolset analysis

Most of the conventional web-attack toolset (`nikto`, `sqlmap`, `ffuf`/`gobuster`, `wpscan`, `hydra`) is
low-yield here: a hand-rolled HTTP server with a handful of fixed routes, no database, a 20-char random
password, and rustls TLS. Mapped to our actual surface (a custom Rust P2P swap daemon + Nostr relay +
bitcoind RPC, all exposed only over Tor):

| Surface | Best tool | Status |
|---|---|---|
| Our parsers (HTTP, `Message`, Nostr, DLEQ, bech32m) | `cargo-fuzz` + `afl.rs` (coverage-guided) | **done** for the two riskiest; more to add |
| The onion services | OnionScan / onionscout | recommended (run from a Tor-capable host) |
| Tor anonymity of a long-lived onion | Vanguards | recommended |
| DoS resilience | slowhttptest | covered by the cap + `daemon_dos.rs` |
| Nostr relay / swap wire (black-box) | boofuzz / radamsa | complements the coverage-guided fuzzers |
| Node RPC TLS | testssl.sh / sslyze | recommended, low risk (rustls) |
| The swap protocol itself | the malicious-counterparty harness | primitive done, extend live |

## 8. Open items

- Wire the fuzz targets into CI and add targets for the remaining parsers.
- Auth-attempt rate-limiting on the web UI (defense in depth; the random password already makes
  brute-force infeasible).
- Run OnionScan + Vanguards against the live onions from a Tor-capable host.
- The two-party regtest wiring of the malicious-counterparty harness (enhanced during live testing).

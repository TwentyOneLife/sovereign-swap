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

## 4. Web UI authentication and the config boundary

- **Finding:** the web UI served the page (and the API token embedded in it) with no auth, so knowing
  the onion was enough to drive the swaps; the Settings view also read back the full config, including
  the node RPC passwords, to the web layer.
- **Fix (auth):** HTTP Basic auth on the page and its assets, with a password generated randomly per
  install (StartOS package) and changeable by the operator; the token is never served without the
  password, so the whole UI is behind it. Constant-time credential comparison.
- **Fix (config off the web entirely):** configuration lives only in the StartOS package actions, which
  write `settings.json`; the daemon reads it on start. The web UI is **swaps-only** (Market and Swaps):
  the Settings tab/form and the `GET`/`PUT /settings` endpoints were removed, so node credentials are
  never serialized to the web layer and there is no config-editing surface to lock or misconfigure.
- **Verified live** (through the deployed daemon): the page with no credentials returns `401` with
  `WWW-Authenticate: Basic`; with the generated password returns `200`; the API with no token returns
  `401`.
- **Auth boundary does not depend on where the request comes from.** The daemon binds a non-loopback
  address only with `SWAP_API_TRUST_NETWORK=1`, and that flag is a bind permission, not an auth bypass
  (`sovereign-swap-daemon.rs`). Every request is gated by the same password and token regardless of
  origin, which is what makes the LAN front door in section 8 safe to expose.
- **Finding (fail-open default), from the black-box pass in section 7:** the page carries the API
  token, and it is behind Basic auth only when a web password is set. A daemon bound off-loopback with
  no password would serve the token to anyone on the network. The StartOS package always sets a
  password, so the deployed service was never exposed, but the daemon's own default failed open, which
  is the wrong default for a service that can move coins.
- **Fix (fail closed):** `Daemon::serve` now refuses to start when the bind is off-loopback and no web
  password is set (`serve_guard`), rather than serving an open, token-bearing API. Loopback binds are
  unaffected (reachable only locally). Unit tests cover the loopback classification and both the
  refused and allowed combinations.

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
  wallet creation, and an authenticated RPC round trip all succeed. Node RPC auth is a **static
  `rpcauth` user** generated on each node (not the rotating `.cookie`), so the credential survives node
  restarts; a wrong password returns 401.
- The engine starts (`/status` reports it), with node and relay connectivity true.
- The web UI auth and the swaps-only boundary behave as in section 4.
- Swap-lifecycle logging now records a new swap and every phase transition to the service log, so a swap
  can be followed in `package logs`, not only the web UI (added for operator monitoring; no secrets are
  logged).

## 7. Kali toolset analysis

Most of the conventional web-attack toolset (`nikto`, `sqlmap`, `ffuf`/`gobuster`, `wpscan`, `hydra`) is
low-yield here: a hand-rolled HTTP server with a handful of fixed routes, no database, a 20-char random
password, and rustls TLS. Mapped to our actual surface (a custom Rust P2P swap daemon + Nostr relay +
bitcoind RPC; the swap daemon API is reached over Tor by default and, since client package 0.2.0:5,
also over a StartOS-terminated HTTPS LAN address, see section 8):

| Surface | Best tool | Status |
|---|---|---|
| Our parsers (HTTP, `Message`, Nostr, DLEQ, bech32m) | `cargo-fuzz` + `afl.rs` (coverage-guided) | **done** for the two riskiest; more to add |
| The onion services | OnionScan / onionscout | **done** (onion audit from a Tor host: no address/IP leak, auth holds over Tor) |
| Tor anonymity of a long-lived onion | Vanguards | **done** (Vanguards-Lite active via the node's Tor 0.4.9.x) |
| DoS resilience | slowhttptest | covered by the cap + `daemon_dos.rs` |
| Nostr relay / swap wire (black-box) | boofuzz / radamsa | complements the coverage-guided fuzzers |
| Node RPC TLS, and the web-UI TLS LAN address | testssl.sh / sslyze | low risk (StartOS rustls proxy); the LAN address is now a direct target, no Tor host needed |
| The web UI auth over the LAN (off Tor) | `hydra` / `medusa`, an `nmap` service scan | reachable since 0.2.0:5; blocked by the 20-char random password, rate-limiting is the open item (section 9) |
| The swap protocol itself | the malicious-counterparty harness | primitive done, extend live |

**Black-box red-team pass.** An operator ran a black-box engagement from Kali against an isolated
replica (the client daemon and the relay on a sandboxed lab segment, never the production node), driven
by a tester with no access to the source. It confirmed the hardening above holds from the outside: no
path traversal, no version banner, terse JSON errors, `nosniff` set, no permissive CORS, only static
assets unauthenticated, and the relay rejecting forged, unsigned, and wrong-kind events. It found the
fail-open default now fixed in section 4 (the API token was readable from the unauthenticated page when
no web password was set). It also noted the relay's connection and rate limits were not observed to
trip under a short burst (80 connections, 60 messages) from one peer; the caps exist in code, so the
open item is confirming they are configured to sane values on a deployed relay, and considering a
per-peer connection ceiling and a NIP-42 AUTH challenge. Done responsibly against a replica, not the
live service.

## 8. LAN HTTPS front door (added in client package 0.2.0:5)

To make the StartOS "Open UI" button work, the web UI is exported with `protocol: 'http'`, which has
StartOS provision a TLS LAN address (its reverse proxy terminates with the node leaf certificate) in
addition to the Tor onion. The onion stays the default address; the LAN address is the new surface.

- **Trust boundary, verified in source:** adding the LAN address does not open unauthenticated access.
  `SWAP_API_TRUST_NETWORK=1` only permits the non-loopback bind; it is not an auth bypass. The page and
  its assets stay behind HTTP Basic (the web password), every API route is token-gated before any work,
  and the token is never served without the password, so a LAN client faces the same `401`s as an onion
  client.
- **Reverse proxy:** `protocol: 'http'` makes StartOS add `X-Forwarded-For` / `X-Forwarded-Proto` and do
  HTTP-aware proxying. The daemon makes no security decision from those headers (auth is the password and
  the token, constant-time compared; there is no IP allowlist and no `X-Forwarded-User` trust), so a
  spoofed forwarded header changes nothing. A regression check worth keeping when that path is touched.
- **What it changes for testing:** TLS and port-scan tools that previously needed a Tor-capable host now
  have a direct LAN target (section 7). Brute-force against the auth is reachable off Tor, which raises
  the priority of auth-attempt rate-limiting below.
- **Testing discipline:** passive audits (testssl.sh / sslyze, an `nmap` service scan) are fine against
  the operator's own node. Brute-force and DoS against the live funds-handling endpoint are not run here:
  the connection cap bounds flooding and the random password defeats guessing.

## 9. Open items

- Wire the fuzz targets into CI and add targets for the remaining parsers.
- Auth-attempt rate-limiting on the web UI. Now higher priority: the LAN front door (section 8) makes the
  login reachable without Tor, so brute-force no longer pays the Tor latency cost (the random password
  still makes it infeasible, this is defense in depth).
- Passive TLS and service-scan audit (testssl.sh / sslyze / `nmap`) of the LAN HTTPS address.
- The two-party regtest wiring of the malicious-counterparty harness (enhanced during live testing).

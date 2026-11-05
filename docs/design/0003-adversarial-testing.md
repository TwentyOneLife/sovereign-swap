# 0003 Adversarial testing and hardening

Status: accepted for implementation, 2026-11-05. First increment (parser fuzzing) landed with this
document.

## Why

A swap engine is attacked for money, not for downtime. The question each test answers is: can a
counterparty, a hostile relay, or someone flooding the service make our side lose coins, get stuck,
or be driven offline? Every attack below is paired with the property it must not break. Tests target
only our own code and our own isolated lab.

## What an attacker controls

- **The counterparty** chooses amounts, timings, which transactions to broadcast and when, the bytes
  of the contract script it funds, and the witnesses it puts on chain. It can lie, stall, race us,
  double-spend its own lock, and send protocol messages out of order or replayed.
- **The relay and transport** (from M3) can drop, reorder, duplicate and forge-at-the-transport
  messages, and is assumed fully hostile: every guarantee rests on the end-to-end envelope.
- **The network** can flood a running service with connections and requests.
- **The chains** can reorg; xBTC cheaply, given its hashrate.

## The invariant

For every swap and every interleaving of events, our side ends in exactly one of: both legs settled
in our favour, or our locked coins recovered by refund. It is never possible for us to have paid the
counterparty without being able to claim, or to have locked coins we can neither claim nor refund.

## Layers

### A. Protocol and funds, in-repo, deterministic (now)

No network, no Kali; runs in CI on every change.

- **Parser fuzzing** (`tests/fuzz_parsers.rs`, landed): millions of hostile byte strings through the
  contract-script parser, the counterparty-script check, and preimage extraction. None may panic,
  loop, or accept input that does not round-trip or whose hash is not the secret. A counterparty
  controls exactly these bytes.
- **Adversarial counterparty** (`tests/swap.rs`, partly landed): a peer that under-locks, over-locks,
  never locks, never claims, comes back too late, races its refund against our claim, double-spends
  its own lock, broadcasts conflicting transactions, and sends duplicate or out-of-order messages.
  Each case asserts the invariant for our side.
- **Downtime and replay** (landed): a taker whose engine is down while its refund window passes still
  refunds on return, since the deadline lives in the swap file; replayed offers, bids and accepts
  create no duplicate swap.
- **Reorg** (landed for the claim case): blocks holding a lock or a claim are invalidated at each
  depth up to the policy's final depth; our side must recover or complete, never settle early.
- **Property test of the state machine** (`tests/property.rs`, landed): random, even self-inconsistent,
  chain views fed to `Swap::decide` must never panic, never claim and refund the same lock in one
  call, and never leave a settled swap (a terminal guard in `decide` enforces the last). A monotonic
  chain simulator drives the taker to a terminal phase and asserts it stays there.
- **Throughput and isolation** (`tests/load.rs`, landed): many swaps between one maker and taker at
  once (default 30, run at 100), every one must settle, no key index reused across swaps, no swap's
  lock funded from another's coin. 100 concurrent swaps settle in 6 confirmation rounds; throughput
  is bounded by block confirmations and node RPC, not by the engine.

### B. Wire and post-quantum envelope (with M3)

- Fuzz the message decoder with malformed, truncated, oversized and duplicated frames.
- Forgery: a message with a broken or swapped signature, a downgraded suite, or a replayed envelope
  must be rejected; the hybrid signature must fail if either half fails.
- Harvest-now: confirm no swap secret or key is ever in a message's cleartext.

### C. Network and service

#### Client side (our code, in CI): done

A relay is untrusted, so the first DoS question is whether a hostile or flooding relay can break our
client. `WsConn` (design 0006) now: caps the WebSocket message size (a hostile oversized frame is
refused, not buffered); keeps a bounded event buffer (a flood drops oldest, never exhausts memory);
and treats an oversized, malformed or non-UTF-8 frame as a dropped frame, never a dropped connection.
`tests/ws_hostile.rs` floods the client with garbage, a malformed event, an oversized frame and a
non-EVENT line, then one valid event: only the valid event survives and the client stays connected.
A hardening this found: capping `max_frame_size` too low makes tungstenite assert (itself a DoS), so
only `max_message_size` is bounded.

Because an interrupted swap always ends in refund, a relay going dark or hostile costs time, not coins.

#### Server side, in the homelab lab (when the relay runs)

Target: a relay deployed on the isolated `hacklab` network (`sovereign-homelab`), attacked from the
Kali VM. Never against a live relay on real infrastructure.

- **Resource exhaustion / DoS**: connection floods, slow-loris, oversized and high-rate events,
  subscription floods. Control: the relay's rate limits, event-size cap, kind allowlist, and
  proof-of-work requirement (see `infra/plans/xbtc-swap-relay-comm.md`). Each attack is run with the
  control off then on, and the difference recorded.
- **Malformed Nostr**: protocol-fuzz the relay's event handling.
- **Censorship / eclipse**: a relay that drops our messages; the client must fall back to other
  relays and no swap must be endangered by one relay going dark.
- **Transport privacy**: confirm Tor-only operation leaks no clearnet metadata.

DoS protects availability, not funds: the invariant already guarantees that a service going down
during a swap ends in refund, never loss. That is itself a test (kill the engine mid-swap, it still
refunds), so availability attacks cannot cost coins, only time.

## On "using AI to attack"

The durable form of an AI-found attack is a committed regression test, not a one-off exploit run. A
model may be used to generate adversarial sequences and malformed inputs offline; anything it finds
becomes a deterministic test here, so the hardening is reproducible and cannot regress. The runtime
never calls out to a model, per the sovereign-code rules.

## Where it lives

- Layers A and B: this repository, run in CI.
- Layer C: a module in `sovereign-homelab` plus a deployable relay target, driven from Kali. It does
  not run in this repository's CI.

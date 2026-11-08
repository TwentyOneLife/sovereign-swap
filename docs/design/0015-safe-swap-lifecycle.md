# 0015 Safe swap lifecycle: maker deadline, offer teardown, relay replay (M1)

Status: design. Records the M1 decisions from the operator review of the first live dust runs
(TwentyOneLife/sovereign-swap#63, #64, #65, #66, #68). M1 makes a swap's whole lifecycle safe and
repeatable on a shared relay so the next dust coverage run (reverse direction and timelock refund on a
clean relay) can be set up, driven, and torn down without hand-editing engine files. No product rate or
custody work here, that is M2.

## Problem

The first runs proved the trustless core but left the lifecycle fragile in five linked ways:

- A maker that takes a bid it cannot fund sits in `Locking` forever. `decide_maker` has no deadline, so
  it retries `Fund` every tick and will lock real coin the instant its wallet is topped up, against a
  counterparty that has already abandoned (#68). This is the real hazard behind the manual teardown.
- An offer is never removed from `own_offers`, so a filled offer stays takeable and can be taken again
  and again, each take funding a fresh lock from the maker wallet (#63).
- There is no operator way to withdraw an offer or abort a pre-lock swap. The only manual workaround,
  deleting the per-swap record, is unsafe (see replay below) and was done by hand during testing (#65).
- The relay persists events and the client subscribes with no `since`/`limit`, so every reconnect
  replays the full retention window. With dedup only against swaps still present in `records`, a deleted
  or settled swap re-animates (#65). Separately, the outbound socket can die silently after a restart
  with `relays` still reporting connected, so new offers stop propagating (#64).
- `/status active_swaps` collapses an engine-call failure to `0` via `unwrap_or(0)`, so an armed,
  fund-retrying maker reads as "nothing active" and the hazard is invisible (#66).

## Approach

Six changes, one bundled protocol bump. Atomic offers only (operator decision 2026-11-08): an offer is
consumed by its first take; partial or pro-rata fills are deferred to a later milestone with their own
design. This removes the only concurrency question from M1.

1. **Maker `Locking` deadline (#68).** In `swap.rs` `decide_maker`, while the maker is still unfunded,
   stop issuing `Fund` and move to `Abandoned` once a new lock could no longer reach `funding_minconf`
   before the taker's `lock_deadline`. The bound is derived from the same offer and depth parameters the
   taker uses, so the maker gives up strictly before the taker does and no lock is ever funded against an
   abandoned swap. Mirrors the existing taker abandon tests (`swap.rs` taker abandon cases).

2. **Atomic offers and prune on fill (#63).** Reject an offer at creation unless
   `min_maker_amount == maker_amount`, so the pro-rata path in `taker_part_min` is unreachable and an
   offer means one whole take. When a take starts a swap, remove the matching `own_offers` entry and
   emit a `Withdraw` (change 5). A filled offer is therefore never re-takeable.

3. **Load-time offer reconciliation.** On `Engine::open`, drop any `own_offers` entry that already has a
   matching `Record` (records carry the offer). Without this, change 6's re-announce would re-broadcast
   an already-filled offer from a still-funded wallet on the first reconnect after upgrade, recreating
   the hazard for existing on-disk state. Change 2 covers the forward path; this covers what is already
   persisted.

4. **Operator teardown primitives (#65).** Add, each as an `EngineCmd` variant, a `handle_engine_cmd`
   arm, an engine method, and a `route()` arm plus handler:
   - **Withdraw offer:** remove from `own_offers`, `save_state()`, emit `Withdraw`.
   - **Abort pre-lock swap:** mark the `Record` terminal (`Abandoned`), allowed only when `funding` /
     `maker_lock` is null. A swap that has locked must go through timelock refund, never a forced
     abandon, so no funded swap can be orphaned.

5. **Relay replay safety (#65, #64).** Two parts:
   - Client `REQ` gains `since` and `limit`, so a reconnect does not replay the whole backlog. As built,
     the `since` watermark lives in the `ws.rs` worker (it tracks the newest `created_at` it has seen and
     resubscribes from it), not in persisted `State`: the worker already sees every event, so this avoids
     coupling the transport to engine state. A one-time backlog replay on a fresh process start is
     harmless because every `handle` path dedups. Cross-restart durability comes instead from a persisted
     `withdrawn` id set in `State` (`#[serde(default)]`) consulted in `handle(Offer)`, plus swap records
     persisting (abort marks `Abandoned`, never deletes), so a settled or withdrawn swap or offer is
     ignored even if replayed after a restart.
   - Add a `Withdraw { offer_id }` variant to `Message` so a peer drops the offer from its `seen_offers`
     and records the id in `withdrawn` (also fixes the sticky discovery in #63). The client watermark plus
     the `withdrawn` set are the re-animation guard. A relay-side TTL / NIP-09 tombstone in
     `relay_server.rs` is deferred to M2 as defence in depth: it is not needed for correctness here (the
     relay already expires events after its 7-day retention, and the client guards replays regardless).

6. **Socket liveness and reconnect (#64).** In `ws.rs`, add ping, reconnect with capped backoff, and
   resubscribe (with the watermark from change 5) to the owner loop instead of letting the worker thread
   exit silently on any error; a shutdown flag set on `WsConn` drop ends the loop cleanly. Re-announcing
   own offers on reconnect is not needed: our offer events already live on the relay (the socket healing
   is what matters), and load-time reconciliation (change 3) keeps filled offers from being re-served.
   Making `/status` `relays` reflect a verified-live socket (rather than the configured count) needs a
   liveness signal plumbed daemon -> engine -> transport; deferred to M2, since reconnect makes any dead
   state transient.

7. **`/status active_swaps` (#66).** Replace `unwrap_or(0)` in `status()` so an engine-call failure is
   surfaced as a distinct state (a null or an error field, as `reference_rate` already does) rather than
   reported as zero active. Update the GUI consumer.

## Protocol compatibility

Lighter than first feared. `FeeTerms` is already chain-keyed (`btc_address` / `xbtc_address` with
`address(chain)`), so per-chain fee needs no wire change. The `since`/`limit` on the `REQ` is standard
NIP-01 and backward compatible with the relay. The only wire change is the additive `Withdraw` variant
on `Message`: a peer that does not understand it simply fails to deserialize that one event and does not
prune, which degrades gracefully to "the maker stops honoring and the taker abandons at its deadline"
(now bounded by change 1). Both our nodes upgrade together, so the degraded path is only a safety net.
Bump the envelope note / protocol version alongside the `Message` change and record it here.

## Alternatives considered

- **Partial fills in M1.** Rejected for M1: decrement-and-rebroadcast plus the race between two takers on
  one offer is exactly the concurrency surface M1 exists to avoid, and no run to date has used a partial
  take. Deferred, not removed, the `taker_part_min` pro-rata math stays in place behind the atomic guard.
- **Relay-only teardown (NIP-09 tombstone) without a client watermark.** Rejected as the primary guard: it
  depends on every relay honoring deletes. The client watermark makes re-animation impossible regardless
  of relay behavior; the TTL/tombstone is kept as defence in depth.
- **Force-refund an already-locked swap from the operator API.** Out of scope and unsafe: a locked swap
  has an on-chain timelock refund path already; a second mechanism risks double-spend confusion. Abort is
  restricted to the pre-lock state.

## Risks

- A maker deadline that fires too early would abandon a fundable swap. Mitigation: derive it from the
  same parameters as the taker deadline and keep a margin, and cover the boundary with unit tests.
- New persisted `State` fields must not break loading of an existing `engine.json`. Mitigation:
  `#[serde(default)]` on every new field, with a test that loads a pre-M1 state file.
- Reconnect logic can loop or thrash on a flapping relay. Mitigation: backoff, and a single owner loop
  that owns the socket state.

## Test plan

- Unit (daemon): maker-deadline abandon at the boundary (mirrors the taker abandon tests); prune-on-fill
  removes the offer; load-time reconciliation drops a filled offer; a replayed settled/withdrawn
  swap and a replayed withdrawn offer are ignored; `status()` surfaces an engine-call error rather than
  `0`; an existing `engine.json` still loads after the `State` fields are added.
- Build in containers: `cargo build --locked --release` and `cargo test`; existing abandon/refund tests
  must still pass.
- Live gate (dust, clean relay), in order: upgrade both nodes, withdraw any remaining stale offers via
  the new endpoint, purge the relay event store, then run Test B (reverse xBTC to BTC) and Test C2
  (timelock refund). Confirm teardown uses the endpoints with no file edits, an unfunded maker
  self-abandons on schedule, a client restart re-animates nothing, and `active_swaps` reads correctly
  throughout. Run the monitoring agent and log to the infra findings runbook.

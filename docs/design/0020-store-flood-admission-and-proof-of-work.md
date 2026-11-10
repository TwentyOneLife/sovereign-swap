# 0020 Store-flood admission and proof of work (abuse deterrence, 0007 item 2)

Status: proposal, 2026-11-10. Phase 1 (decision 1) shipped in #153; the periodic re-announce
(decision 2) shipped separately; phase 2 proof of work (decisions 3 and 4) is still open. The owner
decisions are listed at the end. Addresses gap 2
of the #149 relay-flood audit, the one gap the per-connection controls in #150 and #151 cannot close.
Builds on [0006](0006-nostr-client-and-relay.md) (Nostr transport) and
[0007](0007-abuse-deterrence-no-fund-freezing.md) item 2 (proof of work). Leaves 0007 as written.

## Problem

The relay store (`src/relay_server.rs`) keeps every kind-4859 event for a retention window, bounded by
`store_cap` events and evicted FIFO. An attacker who publishes a stream of validly-signed events, from
throwaway routing keys, fills `store_cap` and pushes the oldest events out. Those events can be honest
offers. Nothing in #150 or #151 stops this: the events are well-formed and correctly signed, each
connection stays inside its rate and subscription limits, and because the relay is Tor-first there is no
per-source identity, so a reconnect resets every per-connection counter. The flood costs the attacker
only bandwidth.

## Severity (bounded by the 0007 backstop)

Eviction costs discovery and reconnect backfill, never a coin. An interrupted or undiscovered swap still
resolves to claim-or-refund (0002, 0003); the relay holds no funds and no keys. Two further mitigations
already in place soften it:

- **Live subscribers are served by fan-out, not the store.** A taker already connected and subscribed
  receives a new offer as it is published, regardless of the store. Eviction only hurts a taker who
  subscribes *after* the offer was pushed out and before the maker re-announces.
- **Re-announcement.** VERIFIED (2026-11-10): nothing re-announced a live offer before this design.
  A reconnect only re-subscribes (`src/ws.rs`), it does not re-publish; `engine.rs` `reconcile_offers`
  runs once at open and only drops taken offers. So an evicted offer never returned on its own, and a
  taker who subscribed after the eviction never discovered it. This is now fixed: `Engine::tick`
  re-announces our own live offers on a timer (`REANNOUNCE_INTERVAL`, 5 min), making eviction
  self-healing. Each re-send is a fresh event, so a relay's id-dedupe does not drop it and a
  reconnecting peer's `since` watermark does not hide it; peer handling of a repeated offer is already
  idempotent, so there is no wire change. This was the single highest-value change here (decision 2).

So this is an availability and discovery problem, not a custody one. That argues for cheap relay-side
mitigations first and for treating proof of work as a limited, later deterrent rather than a fix.

## Phase 1: relay-side admission, no wire change

These need no client change and no protocol bump; they can ride the next `sovereign-swap-relay` deploy
alongside #150 and #151.

### 1a. Bound the store by bytes, not just event count

`store_cap` counts events (100,000) while `max_event_bytes` is 131,072. A store full of maximum-size
events is on the order of 13 GB resident, which likely exceeds the relay host's available RAM and is
itself a memory-exhaustion vector (fill with large valid events rather than many small ones). Add a
total-byte budget to `Store` and evict until both the count and the byte budget are satisfied. Pick the
byte budget from the relay host's actual RAM. This is a few lines and removes the worst case regardless
of anything else here.

### 1b. Partition the store by message class, with per-class quotas and retention

Directed messages (bid, accept, swap steps) carry a `p` recipient tag; broadcast offers do not (0006).
Hold two sub-stores (or one store with per-class budgets):

- **Offers** (no `p` tag): the discovery surface. Give them the larger share and the full retention.
- **Directed** (`p`-tagged): only useful inside the swap's timelocks, and already delivered to a live
  recipient by fan-out. Give them a smaller quota and a shorter retention (hours, not a week).

With separate budgets, a directed-message flood can no longer evict offers or in-flight backfill, and an
offer-class flood is the only remaining case that proof of work would address. Partitioning also matches
the latency profiles: directed steps are timelock-critical and must stay cheap to send.

## Phase 2: proof of work on offer-class events (wire change)

Only if phase 1 proves insufficient against an offer-class flood. This is a wire change on both sides and
must be bundled with the next protocol bump under the one-bump policy.

### Mechanism

NIP-13: require the event `id` (already `SHA-256` over `[0, pubkey, created_at, kind, tags, content]`,
0006) to have at least `D` leading zero bits. The publisher grinds a `["nonce", "<counter>", "<D>"]`
tag; the relay rejects an offer-class event whose `id` has fewer than the floor `D` leading zero bits.

### The cost asymmetry is inverted here (the central caveat)

Two properties make naive PoW favour the attacker, not the honest publisher:

1. **SHA-256 is the ASIC function.** NIP-13 grinds the same hash Bitcoin miners grind. Commodity mining
   hardware does roughly 10^14 hashes/s; a mid-range GPU roughly 10^9 to 10^10. Any difficulty a phone
   can meet in seconds is beaten by mining hardware in microseconds. An attacker with the hardware this
   project's own ecosystem builds pays almost nothing.
2. **Honest content is large; spam content is tiny.** The nonce sits in `tags`, before `content`, so
   every grind attempt rehashes the whole event, and honest content is a hex-encoded post-quantum
   envelope (ML-DSA 4627 B for a broadcast offer, roughly 9 to 10 KB as hex plus the wrapper). A
   spammer's content can be a few bytes. Per grind attempt the honest publisher hashes about 50x more
   data.

Order-of-magnitude, at ~1 GB/s SHA-256 per core:

| | per attempt | D=16 (~65k tries) | D=20 (~1M tries) |
|---|---|---|---|
| honest offer (~9.5 KB) | ~9.5 us | ~0.6 s | ~10 s (far worse on a phone) |
| spam (~0.2 KB) | ~0.2 us | ~0.01 s | ~0.2 s |

And eviction by "lowest PoW first" lets an attacker displace every floor-difficulty honest offer by
grinding just one bit above the floor: cost on the order of `store_cap * 2^(D+1)` hashes, which at D=20
is about 2x10^11 hashes, hours on one CPU core, seconds on a GPU, negligible on an ASIC.

Conclusion to state plainly: PoW raises a casual flooder's cost and is a useful speed bump against
scripted abuse, but it does not prevent the attack against any attacker with a GPU or mining hardware. It
must be paired with a size-aware admission rule (a byte quota so spam must also bring bytes, and/or a
difficulty that scales with event size so a tiny spam event needs more leading-zero bits than a large
honest one). Without the size rule, PoW-weighted retention is a gift to the spammer.

### Client constraints this forces

- **The client is blind to rejection.** `WsConn::publish` (`src/ws.rs`) sends the EVENT and discards the
  relay's `OK` reply; the read path ignores `OK`/`NOTICE`/`CLOSED`. So a relay that raises difficulty
  under load would silently drop an honest publish, the same failure class as the CLOSED problem #151
  worked around. Therefore difficulty must be **fixed per protocol version**, OR the client must be
  changed to parse `OK:false` and re-grind. Dynamic per-load difficulty is off the table until the
  client reacts to `OK`.
- **Multiple relays, one id.** The same event id goes to every relay in the set, so the client must
  grind to the highest floor among its relays. The relay advertises its floor in the NIP-11 document
  (the standard limitation field, believed to be `min_pow_difficulty`; verify against NIP-11/NIP-13).
- **Directed steps stay cheap.** After phase-1 partitioning, directed (`p`-tagged) events keep a zero or
  very low floor; they are timelock-critical and are not the eviction surface.

### Migration

The relay cannot gate by protocol version: the envelope `VERSION`/`SUITE` bytes (0005) are inside the
sealed content it never reads. So roll out by capability, not by version: ship the relay advertising
floor 0 (enforcing nothing), upgrade clients to grind and to read the advertised floor, then raise the
floor. During the soft launch every client is ours, so a coordinated cutover is possible now; this
stops being true once outside peers run their own clients, after which only the advertise-then-raise
path is safe.

## Rejected / deferred alternatives

- **Per-pubkey store quota.** Routing keys are throwaway on a public relay, so a per-pubkey cap is
  trivially bypassed by rotating keys. Useful only as weak defence in depth, not a primary control.
- **Fidelity bonds (0007 item 5).** A forfeitable on-chain bond is a stronger, non-custodial deterrent
  but adds real protocol complexity; out of scope here, still a later option.
- **Memory-hard PoW (Argon2/Equihash-style).** Would blunt the ASIC/GPU asymmetry but breaks NIP-13
  compatibility and raises honest-client cost on low-power devices; note as a possibility only.

## Recommendation

Do phase 1 now (it is cheap, needs no wire change, and 1a closes a real memory-exhaustion vector), and
add a periodic offer re-announce so eviction self-heals. Treat phase 2 (PoW) as a later, limited
deterrent to bundle with the next wire bump only if an offer-class flood proves to be a problem in
practice, and only together with a size-aware admission rule. Do not expect PoW to stop a determined,
hardware-equipped attacker; the honest defence is cheap storage, class partitioning, self-healing
re-announcement, and the 0007 backstop that no flood ever costs a coin.

## Owner decisions

1. Approve phase 1 (byte-bounded store + class partition + shorter directed retention) as a near-term,
   no-wire-change change? (Recommended: yes.) DECIDED yes; shipped in #153.
2. Add a periodic offer re-announce so an evicted offer self-heals? (Recommended: yes; confirm the
   current re-announce is reconnect-only first.) DECIDED yes. On the check: there was no re-announce
   at all (not reconnect, not periodic); implemented as a 5-minute periodic re-announce in `Engine::tick`.
   Note the two behaviour changes it brings: a forgotten own offer now keeps advertising until it is
   withdrawn (before, it quietly stopped being discoverable once relay retention passed), and during a
   long relay outage periodic re-announces queue on the client's unbounded send channel and flush as one
   burst on reconnect (self-correcting, since the relay rate-limits and the next period heals any drop).
   A per-offer max-age and connection-aware gating were considered and left as optional follow-ups.
3. Pursue phase 2 PoW at all, given the SHA-256 ASIC asymmetry, or stop at phase 1 plus fidelity bonds
   later? (Recommended: defer PoW; revisit only on evidence of real offer-class flooding.)
4. If PoW is pursued: fixed-per-version difficulty (no client OK-handling change) or teach the client to
   read `OK:false` and re-grind (enables dynamic difficulty)?
